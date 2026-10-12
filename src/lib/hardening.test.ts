import { strict as assert } from 'node:assert';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import * as https from 'node:https';
import * as net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { tryCall, type CheckContext } from './checks/common';
import { maskLogLine } from './diagnostics';
import { FindingStore } from './findings';
import { classifyIp, learnHomeIpv6 } from './ip';
import { classify, parseDeviceLog, parseDeviceLogXml } from './logparser';
import { hasSettingsRight } from './checks/settings';
import { CertificateMismatchError, PinnedAgent, certPin, type Tr064Client } from './tr064/client';
import { Tr064Fault } from './tr064/soap';

const xmlLog = (group: string, msg: string, id = 1): string =>
    `<DeviceLog><Event><id>${id}</id><group>${group}</group><date>04.09.26</date><time>21:26:05</time><msg>${msg}</msg></Event></DeviceLog>`;

describe('ip extraction', () => {
    it('reads compressed IPv6 addresses', () => {
        const c = classify('Anmeldung an der FRITZ!Box-Benutzeroberfläche von IP-Adresse 2001:db8::abcd gescheitert.');
        assert.equal(c.ip, '2001:db8::abcd');
    });

    it('does not take MAC addresses or times for addresses', () => {
        assert.equal(classify('WLAN-Gerät AA:BB:CC:DD:EE:FF hat sich abgemeldet.').ip, undefined);
        const repeated = classify(
            'Anmeldung einer App mit unbekanntem Anmeldenamen gescheitert. [6 Meldungen seit 10.10.26 07:00:00]',
        );
        assert.equal(repeated.ip, undefined);
    });
});

describe('login classification', () => {
    it('ignores WLAN, provider and telephony messages', () => {
        assert.equal(classify('WLAN-Anmeldung ist gescheitert: Maximale Anzahl erreicht.').kind, 'other');
        assert.equal(classify('Anmeldung beim Internetanbieter ist fehlgeschlagen.').kind, 'other');
        assert.equal(classify('Anmeldung der Internetrufnummer 123 war nicht erfolgreich.').kind, 'other');
    });

    it('treats login words outside the sys group as no login', () => {
        const [e] = parseDeviceLogXml(xmlLog('fon', 'Anmeldung der Internetrufnummer war nicht erfolgreich.'));
        assert.equal(e.kind, 'other');
        const [s] = parseDeviceLogXml(
            xmlLog('sys', 'Anmeldung an der FRITZ!Box-Benutzeroberfläche von IP-Adresse 192.168.178.5.', 500),
        );
        assert.equal(s.kind, 'login-ok');
    });

    it('gives the same key in the XML log and the text log', () => {
        const msg = 'Die FRITZ!Box-Einstellungen wurden über die Benutzeroberfläche geändert.';
        const [x] = parseDeviceLogXml(xmlLog('sys', msg, 502));
        const [t] = parseDeviceLog(`04.09.26 21:26:05 ${msg}`);
        assert.equal(x.key, t.key);
    });
});

describe('home IPv6 prefix', () => {
    after(() => learnHomeIpv6([]));

    it('treats addresses from the own prefix as home network', () => {
        assert.equal(classifyIp('2a02:8071:1234:5600::99'), 'public');
        learnHomeIpv6(['2a02:8071:1234:5601:1:2:3:4', 'fe80::1', '192.168.178.2']);
        // same /56, e.g. the guest network
        assert.equal(classifyIp('2a02:8071:1234:5600::99'), 'private');
        assert.equal(classifyIp('2a02:8071:1234:5700::99'), 'public');
    });
});

describe('diagnostics masking', () => {
    it('hides device names, users, peers, hosts and phone numbers', () => {
        const lines = [
            'Neues WLAN-Gerät erstmalig angemeldet (5 GHz), 866 Mbit/s, iPhone-Anna, IP 192.168.178.20, MAC AA:BB:CC:DD:EE:FF.',
            'Anmeldung der Benutzerin anna an der FRITZ!Box-Benutzeroberfläche von IP-Adresse 192.168.178.5.',
            'VPN-Verbindung zu Max-Laptop wurde erfolgreich hergestellt.',
            'Anruf von +49 171 1234567 abgewiesen',
            'Gerät max-pc.fritz.box (192.168.178.9) hat sich angemeldet.',
            'Freigabe für Port 51820 auf 192.168.178.13 (Garage-NAS) hinzugefügt.',
        ].map(maskLogLine);
        const all = lines.join('\n');
        for (const secret of ['Anna', 'anna', 'Max-Laptop', '1234567', 'max-pc', 'Garage-NAS', '192.168']) {
            assert.ok(!all.includes(secret), `${secret} leaked: ${all}`);
        }
        // the structure stays readable
        assert.match(lines[1], /von IP-Adresse <lan-ip>/);
        assert.equal(
            maskLogLine('DSL ist verfügbar (DSL-Synchronisierung besteht mit 69990/26968 kbit/s).'),
            'DSL ist verfügbar (DSL-Synchronisierung besteht mit 69990/26968 kbit/s).',
        );
    });
});

describe('stored findings', () => {
    it('skips entries that do not look like findings', () => {
        const store = new FindingStore();
        store.load({
            items: [
                null,
                { id: 'x', title: 't', detail: 'd', severity: 'toString' },
                {
                    id: 'ok',
                    category: 'ports',
                    title: 't',
                    detail: 'd',
                    severity: 'warning',
                    hash: 'h',
                    firstSeen: 1,
                    lastSeen: 1,
                },
            ],
            acked: ['ok', 5, {}],
        } as any);
        assert.deepEqual(
            store.all().map(f => f.id),
            ['ok'],
        );
        assert.deepEqual(store.dump().acked, ['ok']);
        store.load({ items: 'nope', acked: null } as any);
        assert.equal(store.all().length, 0);
    });
});

describe('tryCall', () => {
    const ctx = (err: Error): CheckContext => ({
        client: { has: () => true, call: () => Promise.reject(err) } as unknown as Tr064Client,
        lang: 'en',
        log: { debug: () => undefined } as unknown as ioBroker.Logger,
    });

    it('returns undefined when the box refuses an action', async () => {
        assert.equal(
            await tryCall(ctx(new Tr064Fault(606, 'Action not authorized', 'GetInfo')), 'X:1', 'GetInfo'),
            undefined,
        );
    });

    it('re-throws when the box does not answer', async () => {
        await assert.rejects(tryCall(ctx(new Error('connect EHOSTUNREACH')), 'X:1', 'GetInfo'), /EHOSTUNREACH/);
    });
});

describe('certificate pinning', function () {
    this.timeout(15_000);
    let dir = '';
    const cert = (n: number): { key: Buffer; cert: Buffer } => ({
        key: readFileSync(join(dir, `k${n}.pem`)),
        cert: readFileSync(join(dir, `c${n}.pem`)),
    });

    before(function () {
        dir = mkdtempSync(join(tmpdir(), 'fbg-'));
        try {
            for (const n of [1, 2]) {
                execFileSync(
                    'openssl',
                    [
                        'req',
                        '-x509',
                        '-newkey',
                        'ec',
                        '-pkeyopt',
                        'ec_paramgen_curve:prime256v1',
                        '-nodes',
                        '-days',
                        '1',
                    ].concat([
                        '-subj',
                        `/CN=box${n}`,
                        '-keyout',
                        join(dir, `k${n}.pem`),
                        '-out',
                        join(dir, `c${n}.pem`),
                    ]),
                    { stdio: 'ignore' },
                );
            }
            // renewed certificate with the key of box 1
            execFileSync(
                'openssl',
                ['req', '-x509', '-key', join(dir, 'k1.pem'), '-days', '2', '-subj', '/CN=box1-renewed'].concat([
                    '-out',
                    join(dir, 'c3.pem'),
                ]),
                { stdio: 'ignore' },
            );
        } catch {
            this.skip();
        }
    });
    after(() => rmSync(dir, { recursive: true, force: true }));
    const renewed = (): { key: Buffer; cert: Buffer } => ({
        key: readFileSync(join(dir, 'k1.pem')),
        cert: readFileSync(join(dir, 'c3.pem')),
    });

    const get = (port: number, agent: https.Agent, timeout = 2000): Promise<number> =>
        new Promise((resolve, reject) => {
            const req = https.get({ host: '127.0.0.1', port, agent, timeout }, res => {
                res.resume();
                resolve(res.statusCode ?? 0);
            });
            req.on('timeout', () => req.destroy(new Error('request timeout')));
            req.on('error', reject);
        });

    it('pins the first certificate and refuses a swapped one on the same client', async () => {
        const server = https.createServer(cert(1), (_req, res) => res.end('ok'));
        await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
        const port = (server.address() as net.AddressInfo).port;
        try {
            const agent = new PinnedAgent(undefined);
            assert.equal(await get(port, agent), 200);
            assert.ok(agent.pinned);
            server.setSecureContext(cert(2));
            await assert.rejects(get(port, agent), (e: Error) => e instanceof CertificateMismatchError);
        } finally {
            server.close();
        }
    });

    it('accepts a renewed certificate with the same key', async () => {
        const server = https.createServer(cert(1), (_req, res) => res.end('ok'));
        await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
        const port = (server.address() as net.AddressInfo).port;
        try {
            const first = new PinnedAgent(undefined);
            assert.equal(await get(port, first), 200);
            assert.match(first.pinned ?? '', /^sha256\//);
            server.setSecureContext(renewed());
            const again = new PinnedAgent(first.pinned);
            assert.equal(await get(port, again), 200);
            assert.notEqual(again.seenFingerprint, first.seenFingerprint);
        } finally {
            server.close();
        }
    });

    it('upgrades a pin from 0.1.x only if it matches', async () => {
        const server = https.createServer(cert(1), (_req, res) => res.end('ok'));
        await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
        const port = (server.address() as net.AddressInfo).port;
        try {
            const probe = new PinnedAgent(undefined);
            await get(port, probe);
            const legacy = new PinnedAgent(probe.seenFingerprint);
            assert.equal(await get(port, legacy), 200);
            assert.ok(legacy.upgraded);
            assert.equal(legacy.pinned, probe.pinned);
            const wrong = new PinnedAgent('AA:BB:CC');
            await assert.rejects(get(port, wrong), (e: Error) => e instanceof CertificateMismatchError);
        } finally {
            server.close();
        }
    });

    it('builds the pin from the public key', () => {
        const a = certPin(
            Buffer.from(readFileSync(join(dir, 'c1.pem'), 'utf8').replace(/-----[^-]+-----|\s/g, ''), 'base64'),
        );
        const b = certPin(
            Buffer.from(readFileSync(join(dir, 'c3.pem'), 'utf8').replace(/-----[^-]+-----|\s/g, ''), 'base64'),
        );
        assert.equal(a, b);
        assert.equal(certPin(undefined), '');
    });

    it('gives up when the TLS handshake stalls', async () => {
        const sockets: net.Socket[] = [];
        const server = net.createServer(s => sockets.push(s));
        await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
        const port = (server.address() as net.AddressInfo).port;
        try {
            const started = Date.now();
            await assert.rejects(get(port, new PinnedAgent(undefined), 500), /TLS handshake timeout/);
            assert.ok(Date.now() - started < 5000);
        } finally {
            sockets.forEach(s => s.destroy());
            server.close();
        }
    });
});

describe('rights check', () => {
    it('pairs every path with its own access value', () => {
        const r = (p: string, a: string): string => `<path>${p}</path><access>${a}</access>`;
        assert.equal(hasSettingsRight(r('BoxAdmin', 'readwrite')), true);
        assert.equal(hasSettingsRight(r('Phone', 'readwrite') + r('BoxAdmin', 'readonly')), true);
        assert.equal(hasSettingsRight(r('BoxAdmin', 'none') + r('Phone', 'readwrite')), false);
        assert.equal(hasSettingsRight(''), false);
    });
});
