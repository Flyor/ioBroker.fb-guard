import { classifyIp } from './ip';
import { parseDeviceLogXml } from './logparser';
import { isRandomMac, parseHostListXml } from './checks/devices';
import { parseXml } from './tr064/soap';
import { AuthError, CertificateMismatchError, type Tr064Client } from './tr064/client';

/** Notes a failed call in the report. Login and certificate problems end the run, the adapter handles them. */
function failed(e: unknown): string {
    if (e instanceof AuthError || e instanceof CertificateMismatchError) {
        throw e;
    }
    return `error: ${maskText((e as Error).message)}`;
}

/** Keys whose values are always hidden completely. */
const SECRET_KEY = /pass|psk|key|secret|token|sid|username|user$|serial|ssid|mac|mail|dyndns|domain|hostname/i;
/** Keys that look secret by name but only hold flags or limits. */
const HARMLESS_KEY = /rights|count|numberof|enable|active|chars|mode|status|required|selectable/i;

/**
 * Hides anything personal in free text: e-mail and IP addresses, MACs, phone numbers, URLs and MyFRITZ names.
 * Private and public addresses stay distinguishable, because that matters for bug reports.
 */
export function maskText(s: string): string {
    return s
        .replace(/[\w.+-]+@[\w-]+(\.[\w-]+)+/g, '<email>')
        .replace(/\b[a-z]+:\/\/[^\s"<>]+/gi, m => {
            const port = /^[a-z]+:\/\/[^/:]+:(\d+)/i.exec(m)?.[1];
            return `${m.split('://')[0]}://<host>${port ? `:${port}` : ''}/***`;
        })
        .replace(/\b[\w-]+\.myfritz\.net\b/gi, '<myfritz>')
        .replace(/\b([0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b/gi, '<mac>')
        .replace(/\b\d{1,3}(\.\d{1,3}){3}\b/g, ip => (classifyIp(ip) === 'public' ? '<public-ip>' : '<lan-ip>'))
        .replace(/\b[0-9a-f]{1,4}(:[0-9a-f]{0,4}){2,7}\b/gi, m => (/^\d+:\d+(:\d+)?$/.test(m) ? m : '<ipv6>'))
        .replace(/\+\d{6,}|\b0\d{6,}\b/g, '<phone>');
}

/**
 * Masks values that must never show up in logs or support requests.
 */
export function redact(out: Record<string, string>): Record<string, string> {
    const res: Record<string, string> = {};
    for (const [k, v] of Object.entries(out)) {
        if (/devicelog$/i.test(k)) {
            // the log is reported separately and line by line
            res[k] = v ? '(omitted)' : '';
        } else if (SECRET_KEY.test(k) && !HARMLESS_KEY.test(k)) {
            res[k] = v ? '***' : '';
        } else {
            res[k] = maskText(v);
        }
    }
    return res;
}

/**
 * Keeps the structure of a log line but hides addresses, names and numbers.
 */
export function maskLogLine(line: string): string {
    return (
        maskText(line)
            .replace(/["„“][^"„“”]*["“”]/g, '"<name>"')
            .replace(/\b(Benutzer(?:in|innen|s)?|users?)\s+(?!<)\S+/gi, '$1 <user>')
            .replace(/\b[\w-]+(\.[\w-]+)*\.(fritz\.box|local|lan|home|internal)\b/gi, '<host>')
            // new WLAN devices: "..., 866 Mbit/s, iPhone-Anna, IP <lan-ip>, ..."
            .replace(/,\s*[^,<]+?,(\s*IP\b)/g, ', <name>,$1')
            // device name after an address: "auf <lan-ip> (NAS)"
            .replace(/(<lan-ip>|<ipv6>|<mac>)\s*\([^)]*\)/g, '$1 (<name>)')
            // peers: "zu Max-Laptop", "mit max über", but not "von IP-Adresse"
            .replace(
                /\b(zu|von|mit|to|from|with)\s+(?!IP\b|IP-|IP address|Port\b|Zeitserver|time server|unbekannt|unknown|der\b|dem\b|den\b|des\b|einer?\b|the\b|a\b|[<+\d])[^\s,.()<]+/gi,
                '$1 <peer>',
            )
            // phone numbers, but not data rates like 69990/26968
            .replace(/\+?\d[\d /-]{6,}\d/g, m => (/^\d+\/\d+$/.test(m) ? m : '<phone>'))
    );
}

const ACTIONS: [string, string, Record<string, string | number>?][] = [
    ['DeviceInfo:1', 'GetInfo'],
    ['DeviceInfo:1', 'GetSecurityPort'],
    ['UserInterface:1', 'GetInfo'],
    ['UserInterface:1', 'X_AVM-DE_GetInfo'],
    ['LANConfigSecurity:1', 'X_AVM-DE_GetCurrentUser'],
    ['LANConfigSecurity:1', 'GetInfo'],
    ['LANConfigSecurity:1', 'X_AVM-DE_GetAnonymousLogin'],
    ['X_AVM-DE_Auth:1', 'GetInfo'],
    ['X_AVM-DE_RemoteAccess:1', 'GetInfo'],
    ['X_AVM-DE_MyFritz:1', 'GetInfo'],
    ['X_AVM-DE_MyFritz:1', 'GetNumberOfServices'],
    ['X_AVM-DE_Storage:1', 'GetInfo'],
    ['X_AVM-DE_UPnP:1', 'GetInfo'],
    ['ManagementServer:1', 'GetInfo'],
    ['WANIPConnection:1', 'GetPortMappingNumberOfEntries'],
    ['WANPPPConnection:1', 'GetPortMappingNumberOfEntries'],
    ['WLANConfiguration:1', 'GetInfo'],
    ['WLANConfiguration:1', 'X_AVM-DE_GetWPSInfo'],
    ['Hosts:1', 'GetHostNumberOfEntries'],
];

function logSummary(text: string, lines: number): Record<string, unknown> {
    const all = text.split(/\r?\n/).filter(l => l.trim());
    return { lines: all.length, sample: all.slice(0, lines).map(maskLogLine) };
}

/**
 * Runs read-only calls and returns their results with secrets masked.
 * Also returns the first log lines of both log sources so the parser can be checked against real data.
 */
export async function runDiagnostics(client: Tr064Client, logLines = 30): Promise<Record<string, unknown>> {
    const report: Record<string, unknown> = {
        model: client.device?.modelName,
        firmware: client.device?.firmware,
        services: client.device
            ? [...client.device.services.keys()].map(s => s.replace(/^urn:dslforum-org:service:/, ''))
            : [],
    };
    for (const [svc, action, args] of ACTIONS) {
        const key = `${svc} ${action}`;
        if (!client.has(svc)) {
            report[key] = 'not available';
            continue;
        }
        try {
            report[key] = redact(await client.call(svc, action, args ?? {}));
        } catch (e) {
            report[key] = failed(e);
        }
    }
    try {
        const log = await client.call('DeviceInfo:1', 'GetDeviceLog');
        report.logViaAction = logSummary(log.NewDeviceLog ?? '', logLines);
    } catch (e) {
        report.logViaAction = failed(e);
    }
    try {
        const p = await client.call('DeviceInfo:1', 'X_AVM-DE_GetDeviceLogPath');
        const text = p.NewDeviceLogPath ? await client.fetchFromBox(p.NewDeviceLogPath) : '';
        const events = parseDeviceLogXml(text);
        // one masked example per event id, that is what the parser needs
        const byId = new Map<
            string,
            { count: number; repeats: number; group?: string; kind: string; example: string }
        >();
        for (const e of events) {
            const k = String(e.eventId ?? '?');
            const entry = byId.get(k) ?? {
                count: 0,
                repeats: 0,
                group: e.group,
                kind: e.kind,
                example: maskLogLine(e.message),
            };
            entry.count++;
            entry.repeats += e.count;
            byId.set(k, entry);
        }
        report.logViaPath = { events: events.length, newest: events[0]?.rawTime, byEventId: Object.fromEntries(byId) };
    } catch (e) {
        report.logViaPath = failed(e);
    }
    try {
        // structure only: which attributes the box sends per user, never the names
        const ul = await client.call('LANConfigSecurity:1', 'X_AVM-DE_GetUserList');
        const raw = ul['NewX_AVM-DE_UserList'] ?? '';
        const users = parseXml(raw)?.List?.Username;
        const arr: any[] = users === undefined ? [] : Array.isArray(users) ? users : [users];
        report.userList = {
            count: arr.length,
            fields: [...new Set(arr.flatMap(u => (typeof u === 'object' ? Object.keys(u) : ['(text)'])))],
            tags: [...new Set([...raw.matchAll(/<([A-Za-z_][\w-]*)/g)].map(m => m[1]))],
            attributes: [...new Set([...raw.matchAll(/\s([\w-]+)="/g)].map(m => m[1]))],
        };
    } catch (e) {
        report.userList = failed(e);
    }
    try {
        // only counts and field names, never names or addresses
        const p = await client.call('Hosts:1', 'X_AVM-DE_GetHostListPath');
        const xml = p['NewX_AVM-DE_HostListPath'] ? await client.fetchFromBox(p['NewX_AVM-DE_HostListPath']) : '';
        const hosts = parseHostListXml(xml);
        const first = parseXml(xml)?.List?.Item;
        report.hostList = {
            total: hosts.length,
            active: hosts.filter(h => h.active).length,
            privateAddress: hosts.filter(h => isRandomMac(h.mac)).length,
            interfaces: [...new Set(hosts.map(h => h.iface ?? '?'))],
            fields: Object.keys((Array.isArray(first) ? first[0] : first) ?? {}),
        };
    } catch (e) {
        report.hostList = failed(e);
    }
    return report;
}
