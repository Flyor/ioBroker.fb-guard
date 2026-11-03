import { Socket } from 'node:net';
import type { Finding, Severity } from '../findings';
import { classifyIp } from '../ip';
import { assessPort, explainByName, explainPort, type Risk } from '../knowledge/ports';
import { t } from '../i18n';
import { type CheckContext, isOn, tryCall } from './common';

export interface ExposedPort {
    source: 'forwarding' | 'remote-access' | 'myfritz' | 'ftp' | 'tr069';
    protocol: 'TCP' | 'UDP';
    port: number;
    target?: string;
    label: string;
    /** Result of the self-test against the own WAN address (TCP only). */
    reachableFromInside?: boolean;
}

export interface ExposureResult {
    findings: Finding[];
    ports: ExposedPort[];
    wanIp?: string;
}

const riskToSeverity: Record<Risk, Severity> = { high: 'critical', medium: 'warning', low: 'info' };

async function readForwardings(ctx: CheckContext, out: ExposedPort[]): Promise<void> {
    for (const svc of ['WANIPConnection:1', 'WANPPPConnection:1']) {
        const cnt = await tryCall(ctx, svc, 'GetPortMappingNumberOfEntries');
        const n = Math.min(Number(cnt?.NewPortMappingNumberOfEntries ?? 0), 256);
        for (let i = 0; i < n; i++) {
            const e = await tryCall(ctx, svc, 'GetGenericPortMappingEntry', { NewPortMappingIndex: i });
            if (!e || !isOn(e.NewEnabled)) {
                continue;
            }
            out.push({
                source: 'forwarding',
                protocol: e.NewProtocol?.toUpperCase() === 'UDP' ? 'UDP' : 'TCP',
                port: Number(e.NewExternalPort),
                target: `${e.NewInternalClient}:${e.NewInternalPort}`,
                label: e.NewPortMappingDescription || '',
            });
        }
    }
}

async function readWanIp(ctx: CheckContext): Promise<string | undefined> {
    for (const svc of ['WANIPConnection:1', 'WANPPPConnection:1']) {
        const r = await tryCall(ctx, svc, 'GetExternalIPAddress');
        const ip = r?.NewExternalIPAddress;
        if (ip && ip !== '0.0.0.0') {
            return ip;
        }
    }
    return undefined;
}

/**
 * TCP connect to the box's own WAN address. Never used for any other host.
 */
function probeOwnWan(ip: string, port: number, timeoutMs = 3000): Promise<boolean> {
    return new Promise(resolve => {
        const s = new Socket();
        const done = (ok: boolean): void => {
            s.destroy();
            resolve(ok);
        };
        s.setTimeout(timeoutMs, () => done(false));
        s.once('connect', () => done(true));
        s.once('error', () => done(false));
        s.connect(port, ip);
    });
}

export async function checkExposure(ctx: CheckContext, selfTest: boolean): Promise<ExposureResult> {
    const ports: ExposedPort[] = [];
    const findings: Finding[] = [];

    await readForwardings(ctx, ports);

    const remote = await tryCall(ctx, 'X_AVM-DE_RemoteAccess:1', 'GetInfo');
    if (remote && isOn(remote.NewEnabled) && Number(remote.NewPort)) {
        ports.push({
            source: 'remote-access',
            protocol: 'TCP',
            port: Number(remote.NewPort),
            label: t('Remote access to the FRITZ!Box (HTTPS)'),
        });
    }

    const myfritz = await tryCall(ctx, 'X_AVM-DE_MyFritz:1', 'GetNumberOfServices');
    const svcCount = Math.min(Number(myfritz?.NewNumberOfServices ?? 0), 64);
    for (let i = 0; i < svcCount; i++) {
        const s = await tryCall(ctx, 'X_AVM-DE_MyFritz:1', 'GetServiceByIndex', { NewIndex: i });
        if (s && isOn(s.NewEnabled) && Number(s.NewPort)) {
            ports.push({
                source: 'myfritz',
                protocol: 'TCP',
                port: Number(s.NewPort),
                target: s.NewIPv4Addresses || s.NewIPv6Addresses || undefined,
                label: `MyFRITZ!: ${s.NewName || s.NewScheme || '?'}`,
            });
        }
    }

    const storage = await tryCall(ctx, 'X_AVM-DE_Storage:1', 'GetInfo');
    if (storage && isOn(storage.NewFTPWANEnable)) {
        ports.push({
            source: 'ftp',
            protocol: 'TCP',
            port: Number(storage.NewFTPWANPort) || 21,
            label: t('FTP access to the FRITZ!Box storage'),
        });
        if (!isOn(storage.NewFTPWANSSLOnly)) {
            findings.push({
                id: 'ftp:nossl',
                category: 'ports',
                severity: 'critical',
                title: t('FTP from the internet without encryption'),
                detail: t('Storage passwords travel the internet in clear text.'),
                advice: t(
                    'Disable internet access under Home Network > USB/Storage or allow encrypted connections only.',
                ),
            });
        }
    }

    const mgmt = await tryCall(ctx, 'ManagementServer:1', 'GetInfo');
    if (mgmt?.NewConnectionRequestURL) {
        try {
            const u = new URL(mgmt.NewConnectionRequestURL);
            const port = Number(u.port) || (u.protocol === 'https:' ? 443 : 80);
            ports.push({
                source: 'tr069',
                protocol: 'TCP',
                port,
                label: t('ISP remote management (TR-069)'),
            });
        } catch {
            // ignore malformed URL
        }
    }

    const upnp = await tryCall(ctx, 'X_AVM-DE_UPnP:1', 'GetInfo');
    if (upnp && isOn(upnp.NewEnable)) {
        findings.push({
            id: 'upnp:on',
            category: 'ports',
            severity: 'info',
            title: t('UPnP is enabled'),
            detail: t(
                'Devices can read status information. Whether a device may open ports itself is set per device under Internet > Permit Access.',
            ),
            ackable: true,
        });
    }

    // de-duplicate (a MyFRITZ! share can also show up as port forwarding to the same device)
    const unique = new Map<string, ExposedPort>();
    for (const p of ports) {
        const key = `${p.protocol}:${p.port}:${p.target ?? ''}`;
        if (!unique.has(key)) {
            unique.set(key, p);
        }
    }

    const wanIp = await readWanIp(ctx);
    const wanScope = wanIp ? classifyIp(wanIp) : undefined;
    if (wanIp && (wanScope === 'private' || wanScope === 'cgnat')) {
        findings.push({
            id: 'wan:nat',
            category: 'ports',
            severity: 'info',
            title: t('The box has no public IPv4 address'),
            detail: t(
                'WAN address %s is not public (double NAT or CGNAT). IPv4 port forwardings are usually unreachable then.',
                wanIp,
            ),
            ackable: true,
        });
    }

    for (const p of unique.values()) {
        const byPort = explainPort(p.protocol, p.port);
        const byName = byPort
            ? undefined
            : explainByName(
                  p.protocol,
                  p.source === 'forwarding'
                      ? p.label
                      : p.source === 'myfritz'
                        ? p.label.replace(/^MyFRITZ!: /, '')
                        : undefined,
              );
        const k = byPort ?? byName;
        const why: string[] = [];
        const more: string[] = [];
        if (p.source === 'forwarding') {
            why.push(
                p.label
                    ? t('Port forwarding "%s" to %s.', p.label, p.target ?? '')
                    : t('Port forwarding to %s.', p.target ?? ''),
            );
        } else if (p.source !== 'myfritz') {
            why.push(`${p.label}.`);
        }
        if (k && p.source !== 'tr069') {
            why.push(k.text.startsWith(k.name) ? k.text : `${k.name}: ${k.text}`);
        }
        let severity: Severity = k ? riskToSeverity[k.risk] : 'warning';
        let advice = t('If this is intended, confirm it once. Otherwise remove it.');
        if (p.source === 'tr069') {
            severity = 'info';
            why.push(t('The box only accepts requests from the ISP there.'));
            advice = t(
                'If you own the box (not rented from the ISP), you can switch this off under Internet > Account Information > Provider Services. Otherwise confirm it.',
            );
        }
        if (p.source === 'myfritz') {
            advice = t(
                'If you need the access on the road, confirm it. Otherwise delete the MyFRITZ! share of the device under Internet > Permit Access > Port Sharing.',
            );
            why.push(
                t(
                    'A MyFRITZ! share ("%s"): a device in your home network can be reached from the internet via your MyFRITZ! address.',
                    p.label.replace(/^MyFRITZ!: /, ''),
                ),
            );
        }
        if (p.source === 'remote-access') {
            severity = 'warning';
            advice = t(
                'If you access the box on the road, confirm it. Otherwise switch off internet access under Internet > Permit Access > FRITZ!Box Services.',
            );
            why.push(
                t(
                    'This port lets you open the user interface of your box on the road, the same page as fritz.box at home, just over the internet (https://<your-MyFRITZ!-address>:%s). The box calls it "Internet access to the FRITZ!Box via HTTPS", it is often switched on together with MyFRITZ!. The box picked the port number at random, it has no further meaning.',
                    p.port,
                ),
            );
        }
        if (p.source === 'forwarding' || p.source === 'myfritz') {
            more.push(t('Assessment: %s', assessPort(k)));
            if (byName) {
                more.push(
                    t(
                        'Recognised by the name of the forwarding, not the port. %s usually uses a different port, which is fine.',
                        byName.name,
                    ),
                );
            }
            more.push(
                t(
                    'Target in the home network: %s. If that is another router, also check where it forwards to.',
                    p.target ?? '',
                ),
            );
        } else if (p.source === 'tr069') {
            more.push(
                t(
                    'Assessment: Low risk. TR-069 lets the ISP push settings and updates. The box only accepts connection requests with the ISP credentials and then opens the actual connection to the ISP itself.',
                ),
            );
        } else if (p.source === 'remote-access') {
            more.push(
                t(
                    'Assessment: Medium risk. Anyone on the internet can open the login page of the box and try passwords. Protection: long password, two-factor login, automatic FRITZ!OS updates. The box slows down failed attempts. Access via VPN is safer.',
                ),
            );
        }
        if (p.protocol === 'UDP') {
            more.push(t('The self-test cannot check UDP ports, this finding is based on the box configuration.'));
        }
        findings.push({
            id: `port:${p.protocol}:${p.port}:${p.target ?? p.source}`,
            category: 'ports',
            severity,
            title:
                p.source === 'remote-access'
                    ? t('Box interface reachable from the internet (MyFRITZ!/HTTPS, port %s)', p.port)
                    : k
                      ? p.source === 'myfritz'
                          ? t(
                                'Port %s %s is reachable from the internet (%s), MyFRITZ! share',
                                p.protocol,
                                p.port,
                                k.name,
                            )
                          : t('Port %s %s is reachable from the internet (%s)', p.protocol, p.port, k.name)
                      : p.source === 'myfritz'
                        ? t('Port %s %s is reachable from the internet, MyFRITZ! share', p.protocol, p.port)
                        : t('Port %s %s is reachable from the internet', p.protocol, p.port),
            detail: why.join(' '),
            advice,
            more: more.join('\n') || undefined,
            ackable: true,
        });
    }

    const list = [...unique.values()];
    if (selfTest && wanIp && wanScope === 'public') {
        for (const p of list) {
            if (p.protocol === 'TCP') {
                p.reachableFromInside = await probeOwnWan(wanIp, p.port);
            }
        }
    }
    return { findings, ports: list, wanIp };
}
