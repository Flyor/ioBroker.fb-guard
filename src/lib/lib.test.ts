/// <reference types="mocha" />
import { strict as assert } from 'node:assert';
import { deviceFromMessage, isKnownWithNewAddress, isRandomMac, parseHostListXml } from './checks/devices';
import { evaluateEvents } from './checks/events';
import { isNewer, modelSlug, parseVendorInfo } from './checks/firmware';
import { parseUserList } from './checks/settings';
import { maskLogLine, maskText, redact } from './diagnostics';
import { FindingStore, type Finding } from './findings';
import { classifyIp, ipInList, parseIpList } from './ip';
import { explainByName, explainPort } from './knowledge/ports';
import { findingsHtml, summaryMessage } from './render';
import { classify, freshEvents, parseDeviceLog, parseDeviceLogXml } from './logparser';

describe('ip', () => {
    it('classifies addresses', () => {
        assert.equal(classifyIp('192.168.178.20'), 'private');
        assert.equal(classifyIp('10.1.2.3'), 'private');
        assert.equal(classifyIp('100.64.1.1'), 'cgnat');
        assert.equal(classifyIp('127.0.0.1'), 'loopback');
        assert.equal(classifyIp('169.254.3.4'), 'linklocal');
        assert.equal(classifyIp('8.8.8.8'), 'public');
        assert.equal(classifyIp('fe80::1'), 'linklocal');
        assert.equal(classifyIp('fd00::1'), 'private');
        assert.equal(classifyIp('2a00:1450::1'), 'public');
        assert.equal(classifyIp('999.1.1.1'), 'invalid');
    });

    it('matches lists with CIDR', () => {
        const list = parseIpList(' 1.2.3.4, 10.0.0.0/8 ;2001:db8::1');
        assert.ok(ipInList('1.2.3.4', list));
        assert.ok(ipInList('10.200.1.1', list));
        assert.ok(!ipInList('11.0.0.1', list));
        assert.ok(ipInList('2001:db8::1', list));
    });
});

describe('logparser', () => {
    const log = [
        '10.10.26 08:15:02 Anmeldung des Benutzers admin an der FRITZ!Box-Benutzeroberfläche von IP-Adresse 203.0.113.7 gescheitert (falsches Kennwort).',
        '10.10.26 08:14:40 Anmeldung des Benutzers admin an der FRITZ!Box-Benutzeroberfläche von IP-Adresse 203.0.113.7 gescheitert (falsches Kennwort).',
        '10.10.26 07:00:00 Anmeldung des Benutzers fb-guard an der FRITZ!Box-Benutzeroberfläche von IP-Adresse 192.168.178.20.',
        '09.10.26 22:01:13 Neues WLAN-Gerät erstmalig angemeldet (2,4 GHz), 144 Mbit/s, PC-192-168-178-77, IP 192.168.178.77, MAC AA:BB:CC:DD:EE:FF.',
        '',
    ].join('\n');

    it('parses lines and time', () => {
        const ev = parseDeviceLog(log);
        assert.equal(ev.length, 4);
        assert.equal(ev[0].time?.getFullYear(), 2026);
        assert.equal(ev[0].time?.getHours(), 8);
        assert.notEqual(ev[0].id, ev[1].id);
    });

    it('recognizes failed logins', () => {
        const c = classify(parseDeviceLog(log)[0].message);
        assert.equal(c.kind, 'login-failed');
        assert.equal(c.ip, '203.0.113.7');
        assert.equal(c.user, 'admin');
        assert.equal(c.channel, 'ui');
        assert.equal(c.reason, 'falsches Kennwort');
    });

    it('recognizes successful logins and new devices', () => {
        const ev = parseDeviceLog(log);
        assert.equal(ev[2].kind, 'login-ok');
        assert.equal(ev[2].user, 'fb-guard');
        assert.equal(ev[3].kind, 'new-device');
    });

    it('recognizes app logins (tab separated, as in the box UI)', () => {
        const [e] = parseDeviceLog(
            '11.10.26	00:07:31	Anmeldung einer App des Benutzers guard-user von IP-Adresse 192.168.178.30.',
        );
        assert.equal(e.kind, 'login-ok');
        assert.equal(e.channel, 'app');
        assert.equal(e.user, 'guard-user');
        assert.equal(e.time?.getMinutes(), 7);
    });

    it('reads the XML log with event ids', () => {
        const xml = `<?xml version="1.0" encoding="UTF-8"?><DeviceLog><!-- filter :all -->
            <Event><id>506</id><group>sys</group><date>11.10.26</date><time>00:07:31</time>
            <msg>Anmeldung einer App des Benutzers guard-user von IP-Adresse 192.168.178.30.</msg></Event>
            <Event><id>504</id><group>sys</group><date>10.10.26</date><time>23:10:02</time>
            <msg>Anmeldung des Benutzers admin an der FRITZ!Box-Benutzeroberfläche von IP-Adresse 192.168.178.20.</msg></Event>
            </DeviceLog>`;
        const ev = parseDeviceLogXml(xml);
        assert.equal(ev.length, 2);
        assert.equal(ev[0].eventId, 506);
        assert.equal(ev[0].group, 'sys');
        assert.equal(ev[0].kind, 'login-ok');
        assert.equal(ev[1].channel, 'ui');
        assert.equal(ev[1].time?.getHours(), 23);
        // same event in text and XML form gets the same id
        const [t] = parseDeviceLog(
            '11.10.26\t00:07:31\tAnmeldung einer App des Benutzers guard-user von IP-Adresse 192.168.178.30.',
        );
        assert.equal(t.id, ev[0].id);
        assert.deepEqual(parseDeviceLogXml('<DeviceLog></DeviceLog>'), []);
    });

    it('understands English messages', () => {
        const c = classify(
            'Login of user admin to the FRITZ!Box user interface from IP address 198.51.100.9 failed (wrong password).',
        );
        assert.equal(c.kind, 'login-failed');
        assert.equal(c.ip, '198.51.100.9');
    });

    it('turns failed logins into one alert per address', () => {
        const alerts = evaluateEvents(
            parseDeviceLog(log),
            {
                ownUser: 'fb-guard',
                knownIps: [],
                alertRemoteLogins: true,
                alertNewDevices: true,
                attackThreshold: 2,
            },
            'en',
        );
        const failed = alerts.filter(a => /failed/i.test(a.title));
        assert.equal(failed.length, 1);
        assert.equal(failed[0].severity, 'critical');
        assert.match(failed[0].text, /Count: 2/);
        assert.match(failed[0].text, /203\.0\.113\.7/);
        assert.equal(alerts.filter(a => a.severity === 'info').length, 1);
    });

    it('reports logins from the internet unless known', () => {
        const ev = parseDeviceLog(
            '10.10.26 09:00:00 Anmeldung des Benutzers bob an der FRITZ!Box-Benutzeroberfläche von IP-Adresse 198.51.100.9.',
        );
        const opts = {
            ownUser: 'x',
            knownIps: [],
            alertRemoteLogins: true,
            alertNewDevices: false,
            attackThreshold: 5,
        };
        assert.equal(evaluateEvents(ev, opts, 'de').length, 1);
        assert.equal(evaluateEvents(ev, { ...opts, knownIps: ['198.51.100.0/24'] }, 'de').length, 0);
    });

    it('uses event ids and repeat counts', () => {
        const xml = `<DeviceLog>
            <Event><id>510</id><group>sys</group><date>10.10.26</date><time>22:55:59</time>
            <msg>Anmeldung einer App mit unbekanntem Anmeldenamen von IP-Adresse 192.168.178.30 gescheitert. [3 Meldungen seit 10.10.26 22:50:01]</msg></Event>
            <Event><id>2018</id><group>net</group><date>10.10.26</date><time>21:00:00</time>
            <msg>Neue Regel eingetragen.</msg></Event>
            <Event><id>502</id><group>sys</group><date>10.10.26</date><time>20:00:00</time>
            <msg>Einstellungen wurden über die Benutzeroberfläche geändert.</msg></Event>
            <Event><id>503</id><group>sys</group><date>10.10.26</date><time>19:00:00</time>
            <msg>Anmeldung an der FRITZ!Box-Benutzeroberfläche von IP-Adresse 192.168.178.40 gescheitert (ungültige Sitzungskennung).</msg></Event>
            </DeviceLog>`;
        const ev = parseDeviceLogXml(xml);
        assert.equal(ev[0].kind, 'login-failed');
        assert.equal(ev[0].count, 3);
        assert.equal(ev[1].kind, 'port-added');
        assert.equal(ev[2].kind, 'settings-changed');
        assert.equal(ev[3].count, 1);
        assert.equal(ev[3].reason, 'ungültige Sitzungskennung');
        // text fallback without ids
        assert.equal(
            classify('Die FRITZ!Box-Einstellungen wurden über die Benutzeroberfläche geändert.').kind,
            'settings-changed',
        );
        assert.equal(classify('Freigabe für Port 51820 auf 192.168.178.50 (nas) hinzugefügt.').kind, 'port-added');

        const alerts = evaluateEvents(
            ev,
            { ownUser: 'x', knownIps: [], alertRemoteLogins: true, alertNewDevices: false, attackThreshold: 3 },
            'en',
        );
        const byIp = (ip: string): (typeof alerts)[number] | undefined => alerts.find(a => a.text.includes(ip));
        assert.equal(byIp('192.168.178.30')?.severity, 'critical');
        assert.match(byIp('192.168.178.30')?.text ?? '', /Count: 3/);
        // expired browser session is only a hint
        assert.equal(byIp('192.168.178.40')?.severity, 'info');
        assert.ok(alerts.some(a => a.title === 'New port forwarding' && a.severity === 'warning'));
        assert.ok(alerts.some(a => a.title === 'Settings changed'));
    });

    it('does not report the same entry again when the box shifts its time', () => {
        const log = (time: string, msg: string): string =>
            `<DeviceLog><Event><id>2018</id><group>sys</group><date>04.09.26</date><time>${time}</time><msg>${msg}</msg></Event></DeviceLog>`;
        const port = 'Freigabe für Port 51820 auf 192.168.178.20 (server) hinzugefügt.';
        const first = freshEvents(parseDeviceLogXml(log('21:26:05', port)), {});
        assert.equal(first.fresh.length, 1);
        // one second off on the next read
        const second = freshEvents(parseDeviceLogXml(log('21:26:04', port)), first.seen);
        assert.equal(second.fresh.length, 0);
        // same text hours later is a new entry
        assert.equal(freshEvents(parseDeviceLogXml(log('23:00:00', port)), second.seen).fresh.length, 1);
        // repeat counter going up is new
        const wrong =
            'Anmeldung des Benutzers a an der FRITZ!Box-Benutzeroberfläche von IP-Adresse 192.168.0.5 gescheitert (falsches Kennwort).';
        const a = freshEvents(parseDeviceLogXml(log('10:00:00', `${wrong} [2 Meldungen seit 04.09.26 09:59:00]`)), {});
        const b = freshEvents(
            parseDeviceLogXml(log('10:00:00', `${wrong} [2 Meldungen seit 04.09.26 09:59:00]`)),
            a.seen,
        );
        const c = freshEvents(
            parseDeviceLogXml(log('10:00:30', `${wrong} [3 Meldungen seit 04.09.26 09:59:00]`)),
            b.seen,
        );
        assert.deepEqual([a.fresh.length, b.fresh.length, c.fresh.length], [1, 0, 1]);
    });
});

describe('findings', () => {
    const f = (id: string, detail = 'd'): Finding => ({
        id,
        category: 'ports',
        severity: 'warning',
        title: id,
        detail,
        ackable: true,
    });

    it('tracks added, changed and resolved', () => {
        const s = new FindingStore();
        let d = s.update('ports', [f('a'), f('b')], 1);
        assert.equal(d.added.length, 2);
        d = s.update('ports', [f('a', 'other'), f('b')], 2);
        assert.equal(d.changed.length, 1);
        assert.equal(d.added.length, 0);
        d = s.update('ports', [f('a', 'other')], 3);
        assert.deepEqual(
            d.resolved.map(x => x.id),
            ['b'],
        );
        assert.equal(s.all()[0].firstSeen, 1);
    });

    it('keeps other categories untouched', () => {
        const s = new FindingStore();
        s.update('settings', [{ ...f('x'), category: 'settings' }]);
        s.update('ports', []);
        assert.equal(s.all().length, 1);
    });

    it('acknowledges and scores', () => {
        const s = new FindingStore();
        s.update('ports', [f('a'), { ...f('c'), severity: 'critical', ackable: false }]);
        assert.equal(s.score(), 65);
        assert.ok(s.acknowledge('a'));
        assert.ok(!s.acknowledge('c'));
        assert.equal(s.open().length, 1);
        assert.equal(s.score(), 75);
        const copy = new FindingStore();
        copy.load(JSON.parse(JSON.stringify(s.dump())));
        assert.ok(copy.isAcked('a'));
        s.update('ports', []);
        s.pruneAcks();
        assert.ok(!s.isAcked('a'));
    });
});

describe('firmware', () => {
    it('builds the vendor folder name', () => {
        assert.equal(modelSlug('FRITZ!Box 7590'), 'fritzbox-7590');
        assert.equal(modelSlug('FRITZ!Box 7590 AX'), 'fritzbox-7590-ax');
    });

    it('compares versions', () => {
        assert.ok(isNewer('8.30', '8.25'));
        assert.ok(isNewer('154.08.30', '8.25'));
        assert.ok(!isNewer('8.25', '154.08.25'));
        assert.ok(!isNewer('7.57', '8.25'));
    });

    it('reads the vendor info file', () => {
        assert.equal(parseVendorInfo('Produkt: FRITZ!Box 7590\r\nVersion: 154.08.25\r\nSprache: de'), '154.08.25');
        assert.equal(parseVendorInfo('nothing'), undefined);
    });
});

describe('settings', () => {
    it('parses the user list', () => {
        const xml = '<List><Username last_user="1">admin</Username><Username>fb-guard</Username></List>';
        assert.deepEqual(parseUserList(xml), ['admin', 'fb-guard']);
        assert.deepEqual(parseUserList(''), []);
    });
});

describe('ports', () => {
    it('explains known ports', () => {
        assert.ok(explainPort('TCP', 8089, 'de')?.text);
        assert.equal(explainPort('UDP', 51820, 'en')?.risk, 'low');
        assert.equal(explainPort('TCP', 3389, 'en')?.risk, 'high');
        assert.equal(explainPort('TCP', 12345, 'en'), undefined);
    });
});

describe('diagnostics', () => {
    it('masks secrets but keeps flags', () => {
        const r = redact({
            NewPassword: 'geheim',
            NewKeyPassphrase: 'wlan123',
            NewSerialNumber: '123',
            'NewX_AVM-DE_IsDefaultPasswordActive': '0',
            NewEnable: '1',
            NewURL: 'https://box/x?sid=abcdef&lang=de',
        });
        assert.equal(r.NewPassword, '***');
        assert.equal(r.NewKeyPassphrase, '***');
        assert.equal(r.NewSerialNumber, '***');
        assert.equal(r['NewX_AVM-DE_IsDefaultPasswordActive'], '0');
        assert.equal(r.NewEnable, '1');
        assert.equal(r.NewURL, 'https://<host>/***');
    });

    it('masks log lines', () => {
        const m = maskLogLine(
            '10.10.26 08:15:02 Anmeldung des Benutzers admin von IP-Adresse 203.0.113.7, MAC AA:BB:CC:DD:EE:FF, 2a00:1450:4001::1',
        );
        assert.doesNotMatch(m, /admin|203\.0\.113\.7|AA:BB|2a00/);
        assert.match(m, /08:15:02/);
        assert.match(m, /<public-ip>/);
    });

    it('masks personal data in values and telephony lines', () => {
        const r = redact({
            NewEmail: 'someone@example.org',
            NewDynDNSName: 'abc123.myfritz.net',
            NewConnectionRequestURL: 'http://198.51.100.20:8089/0123456789abcdef',
            NewDeviceLog: 'line 1\nline 2',
            NewDescription: 'reached via 192.168.178.1 and 198.51.100.20',
        });
        assert.equal(r.NewEmail, '***');
        assert.equal(r.NewDynDNSName, '***');
        assert.equal(r.NewConnectionRequestURL, 'http://<host>:8089/***');
        assert.equal(r.NewDeviceLog, '(omitted)');
        assert.equal(r.NewDescription, 'reached via <lan-ip> and <public-ip>');
        const m = maskLogLine(
            '24.09.26 15:14:55 Internettelefonie mit +4930123456789 über sip.example.net war nicht erfolgreich.',
        );
        assert.doesNotMatch(m, /4930123456789/);
        assert.match(m, /mit <phone> über/);
        assert.match(m, /<phone>|<peer>/);
        const free = maskText('Kontakt: someone@example.org, Box: abc123.myfritz.net, Tel 030123456789');
        assert.doesNotMatch(free, /someone|abc123|030123456789/);
    });
});

describe('devices', () => {
    const xml = `<List>
        <Item><Index>1</Index><IPAddress>192.168.178.21</IPAddress><MACAddress>DA:A1:19:00:11:22</MACAddress><Active>1</Active><HostName>iPhone-Anna</HostName><InterfaceType>802.11</InterfaceType></Item>
        <Item><Index>2</Index><IPAddress>192.168.178.22</IPAddress><MACAddress>00:1A:2B:3C:4D:5E</MACAddress><Active>0</Active><HostName>nas</HostName><InterfaceType>Ethernet</InterfaceType></Item>
        </List>`;

    it('detects private addresses', () => {
        assert.equal(isRandomMac('DA:A1:19:00:11:22'), true);
        assert.equal(isRandomMac('00:1a:2b:3c:4d:5e'), false);
        assert.equal(isRandomMac('nonsense'), false);
    });

    it('reads the host list', () => {
        const hosts = parseHostListXml(xml);
        assert.equal(hosts.length, 2);
        assert.equal(hosts[0].active, true);
        assert.equal(hosts[1].mac, '00:1a:2b:3c:4d:5e');
    });

    it('skips known devices with a new private address', () => {
        const hosts = parseHostListXml(xml);
        const msg =
            'Neues WLAN-Gerät erstmalig angemeldet (5 GHz), 866 Mbit/s, iPhone-Anna, IP 192.168.178.30, MAC 7E:11:22:33:44:55.';
        const d = deviceFromMessage(msg);
        assert.equal(d.mac, '7e:11:22:33:44:55');
        assert.equal(d.name, 'iPhone-Anna');
        assert.equal(isKnownWithNewAddress(hosts, d.mac, d.name), true);
        assert.equal(isKnownWithNewAddress(hosts, d.mac, 'unknown-phone'), false);

        const [e] = parseDeviceLog(`10.10.26 09:00:00 ${msg}`);
        const opts = { ownUser: 'x', knownIps: [], alertRemoteLogins: true, alertNewDevices: true, attackThreshold: 5 };
        assert.equal(evaluateEvents([e], { ...opts, skipKnownPrivate: true, hosts }, 'en').length, 0);
        const [a] = evaluateEvents([e], opts, 'en');
        assert.match(a.text, /private/);
    });
});

describe('render', () => {
    it('recognises services by forwarding name', () => {
        assert.equal(explainByName('UDP', 'WireGuard', 'en')?.risk, 'low');
        assert.equal(explainByName('TCP', 'WireGuard', 'en'), undefined);
        assert.equal(explainByName('TCP', 'Remote Desktop', 'en')?.risk, 'high');
        assert.equal(explainByName('UDP', 'something', 'en'), undefined);
    });

    it('escapes everything that comes from the box', () => {
        const html = findingsHtml(
            [
                {
                    id: 'port:UDP:1:<x>',
                    category: 'ports',
                    severity: 'warning',
                    title: '<img src=x onerror=alert(1)>',
                    detail: 'a\n<script>alert(1)</script>',
                    more: '"quoted"',
                },
            ],
            { score: 90, acked: 0 },
            'en',
        );
        assert.ok(!html.includes('<img'));
        assert.ok(!html.includes('<script'));
        assert.ok(html.includes('&lt;script&gt;'));
        assert.ok(html.includes('a<br>'));
        assert.ok(html.includes('&quot;quoted&quot;'));
        assert.ok(html.includes('<details'));
    });

    it('lists all open findings in the overview, worst first', () => {
        const f = (id: string, severity: Finding['severity']): Finding => ({
            id,
            category: 'ports',
            severity,
            title: `T ${id}`,
            detail: '',
        });
        const m = summaryMessage([f('a', 'info'), f('b', 'warning'), f('c', 'info')], { score: 90, acked: 2 }, 'en');
        assert.equal(m.severity, 'warning');
        assert.ok(m.text.indexOf('Warnings (1)') < m.text.indexOf('Notes (2)'));
        assert.ok(m.text.includes('• T c'));
        assert.equal(summaryMessage([], { score: 100, acked: 0 }, 'en').severity, 'info');
    });
});
