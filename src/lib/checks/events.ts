import { describeScope, classifyIp, ipInList } from '../ip';
import { locale, t } from '../i18n';
import type { LogEvent } from '../logparser';
import { parseDeviceLog, parseDeviceLogXml } from '../logparser';
import { type CheckContext, tryCall } from './common';
import { deviceFromMessage, isKnownWithNewAddress, isRandomMac, type Host } from './devices';

export interface EventAlert {
    severity: 'warning' | 'critical' | 'info';
    title: string;
    text: string;
}

export interface EventOptions {
    ownUser: string;
    knownIps: string[];
    /** Alert on successful logins from the internet that are not on the known list. */
    alertRemoteLogins: boolean;
    alertNewDevices: boolean;
    /** Do not report known devices that only switched to a new private address. */
    skipKnownPrivate?: boolean;
    /** Device list of the box, needed for skipKnownPrivate. */
    hosts?: Host[];
    /** Number of failed attempts from one address that counts as an attack. */
    attackThreshold: number;
}

/**
 * Reads the event log. The XML log contains the logins, GetDeviceLog does not
 * (FRITZ!OS 8 leaves out the system events there), so it is only the fallback.
 */
export async function readDeviceLog(ctx: CheckContext): Promise<LogEvent[]> {
    const p = await tryCall(ctx, 'DeviceInfo:1', 'X_AVM-DE_GetDeviceLogPath');
    if (p?.NewDeviceLogPath) {
        try {
            const events = parseDeviceLogXml(await ctx.client.fetchFromBox(p.NewDeviceLogPath));
            if (events.length) {
                return events;
            }
        } catch (e) {
            ctx.log.debug(`XML log not readable, using GetDeviceLog: ${(e as Error).message}`);
        }
    }
    const r = await tryCall(ctx, 'DeviceInfo:1', 'GetDeviceLog');
    return parseDeviceLog(r?.NewDeviceLog ?? '');
}

function fmtTime(e: LogEvent): string {
    return e.time ? e.time.toLocaleString(locale()) : e.rawTime || '?';
}

const channelName = (c: string | undefined): string => {
    const en: Record<string, string> = {
        ui: 'user interface',
        remote: 'remote access via internet',
        tr064: 'TR-064 (apps/programs)',
        app: 'app',
        ftp: 'FTP',
        smb: 'storage (SMB)',
        vpn: 'VPN',
        unknown: 'unknown',
    };
    const name = en[c ?? 'unknown'];
    return name ? t(name) : (c ?? '');
};

/**
 * Turns new log events into alerts. Failed logins are grouped per source address.
 */
export function evaluateEvents(events: LogEvent[], opts: EventOptions): EventAlert[] {
    const alerts: EventAlert[] = [];
    const failed = new Map<string, LogEvent[]>();
    const wlan = new Map<string, LogEvent[]>();

    for (const e of events) {
        if (e.kind === 'wlan-failed') {
            const key = e.mac ?? '?';
            wlan.set(key, [...(wlan.get(key) ?? []), e]);
        } else if (e.kind === 'login-failed' || e.kind === 'login-blocked') {
            const key = e.ip ?? '?';
            failed.set(key, [...(failed.get(key) ?? []), e]);
        } else if (e.kind === 'login-ok' && opts.alertRemoteLogins && e.ip) {
            if (e.user && e.user === opts.ownUser) {
                continue;
            }
            if (classifyIp(e.ip) === 'public' && !ipInList(e.ip, opts.knownIps)) {
                alerts.push({
                    severity: 'warning',
                    title: t('Login from the internet'),
                    text: `${
                        e.user
                            ? t(
                                  '%s: user "%s" logged in from %s (%s). If this was not you, change the password right away.',
                                  fmtTime(e),
                                  e.user,
                                  e.ip,
                                  channelName(e.channel),
                              )
                            : t(
                                  '%s: a user logged in from %s (%s). If this was not you, change the password right away.',
                                  fmtTime(e),
                                  e.ip,
                                  channelName(e.channel),
                              )
                    }\n\n${e.message}`,
                });
            }
        } else if (e.kind === 'port-added') {
            alerts.push({
                severity: 'warning',
                title: t('New port forwarding'),
                text: `${fmtTime(e)}: ${e.message}\n\n${t('Was this intended? If not, delete the forwarding in the box.')}`,
            });
        } else if (e.kind === 'settings-changed') {
            alerts.push({
                severity: 'info',
                title: t('Settings changed'),
                text: `${fmtTime(e)}: ${e.message}`,
            });
        } else if (e.kind === 'new-device' && opts.alertNewDevices) {
            const d = deviceFromMessage(e.message);
            if (opts.skipKnownPrivate && opts.hosts && isKnownWithNewAddress(opts.hosts, d.mac, d.name)) {
                continue;
            }
            const hint = isRandomMac(d.mac)
                ? `\n\n${t(
                      'The device uses a private (changing) address, e.g. iPhone, Android or Windows. It may be a known device with a new address.',
                  )}`
                : '';
            alerts.push({
                severity: 'info',
                title: t('New device on the network'),
                text: `${fmtTime(e)}: ${e.message}${hint}`,
            });
        }
    }

    for (const [ip, list] of failed) {
        const scope = ip === '?' ? 'invalid' : classifyIp(ip);
        const users = [...new Set(list.map(e => e.user).filter(Boolean))];
        const channels = [...new Set(list.map(e => channelName(e.channel)))];
        const times = list.map(e => e.time?.getTime()).filter((x): x is number => x !== undefined);
        const first = list.reduce((a, b) => ((a.time?.getTime() ?? 0) < (b.time?.getTime() ?? 0) ? a : b));
        const last = list.reduce((a, b) => ((a.time?.getTime() ?? 0) > (b.time?.getTime() ?? 0) ? a : b));
        const count = list.reduce((n, e) => n + e.count, 0);
        const attack = count >= opts.attackThreshold;
        // 503 = old browser tab with an expired session, not a password guess
        const staleOnly = list.every(e => e.eventId === 503);
        const severity = scope === 'public' || attack ? 'critical' : staleOnly ? 'info' : 'warning';
        const span = times.length > 1 ? `${fmtTime(first)} – ${fmtTime(last)}` : fmtTime(last);

        const lines = [
            t('Count: %s', count),
            t('Time: %s', span),
            t('From: %s (%s)', ip, describeScope(scope)),
            t('Access: %s', channels.join(', ')),
        ];
        if (users.length) {
            lines.push(t('User name: %s', users.join(', ')));
        }
        if (last.reason) {
            lines.push(t('Reason: %s', last.reason));
        }
        lines.push(
            '',
            scope === 'public'
                ? t(
                      'Someone on the internet is guessing passwords. The box slows this down. If you do not need remote access, turn it off.',
                  )
                : staleOnly
                  ? t('Usually an old browser tab of the box interface with an expired session. Close or reload it.')
                  : t(
                        'The attempt came from your home network. Usually a typo or a device/program with an old password.',
                    ),
        );
        alerts.push({
            severity,
            title: attack ? t('Multiple failed logins') : t('Failed login'),
            text: lines.join('\n'),
        });
    }
    for (const [mac, list] of wlan) {
        alerts.push(wlanAlert(mac, list, opts));
    }
    return alerts;
}

/**
 * Failed Wi-Fi logins of one device. A known device usually has an old key stored,
 * an unknown one nearby may be guessing the key.
 */
function wlanAlert(mac: string, list: LogEvent[], opts: EventOptions): EventAlert {
    const count = list.reduce((n, e) => n + e.count, 0);
    const known = mac !== '?' && !!opts.hosts?.some(h => h.mac.toLowerCase() === mac);
    const attack = count >= opts.attackThreshold;
    const severity = attack ? (known ? 'warning' : 'critical') : known ? 'info' : 'warning';
    const last = list.reduce((a, b) => ((a.time?.getTime() ?? 0) > (b.time?.getTime() ?? 0) ? a : b));
    const lines = [t('Count: %s', count), t('Last: %s', fmtTime(last)), t('Device (MAC): %s', mac)];
    if (last.reason) {
        lines.push(t('Reason: %s', last.reason));
    }
    lines.push(
        '',
        known
            ? t('The box knows this device. Usually it still has an old Wi-Fi password stored.')
            : isRandomMac(mac)
              ? t(
                    'Unknown device with a private (changing) address. It may be a guest with a typo, or someone in range guessing the Wi-Fi key. On many attempts check the key and turn off WPS.',
                )
              : t(
                    'Unknown device. It may be a guest with a typo, or someone in range guessing the Wi-Fi key. On many attempts check the key and turn off WPS.',
                ),
    );
    return {
        severity,
        title: attack ? t('Multiple failed Wi-Fi logins') : t('Failed Wi-Fi login'),
        text: lines.join('\n'),
    };
}
