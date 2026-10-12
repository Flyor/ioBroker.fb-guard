import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { parseXml } from './tr064/soap';

export type EventKind =
    | 'login-failed'
    | 'login-ok'
    | 'login-blocked'
    | 'wlan-failed'
    | 'new-device'
    | 'settings-changed'
    | 'port-added'
    | 'vpn'
    | 'firmware'
    | 'other';

export type LoginChannel = 'ui' | 'remote' | 'tr064' | 'app' | 'ftp' | 'smb' | 'vpn' | 'unknown';

export interface LogEvent {
    /** Stable id of the line (hash of time + text). */
    id: string;
    /** Hash of the text without time and repeat counter, see {@link freshEvents}. */
    key: string;
    time?: Date;
    rawTime: string;
    message: string;
    kind: EventKind;
    ip?: string;
    user?: string;
    /** Device address, for failed Wi-Fi logins. */
    mac?: string;
    channel?: LoginChannel;
    reason?: string;
    /** The box merges repeated messages ("[2 Meldungen seit ...]"). */
    count: number;
    /** Numeric event id of the box (only in the XML log). */
    eventId?: number;
    /** Event group of the box, e.g. sys, net, tel (only in the XML log). */
    group?: string;
}

const LINE = /^(\d{1,2})\.(\d{1,2})\.(\d{2,4})\s+(\d{1,2}):(\d{2}):(\d{2})\s+(.+)$/;
const LINE_ISO = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})\s+(.+)$/;

const IPV4 = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/;
/** After "IP-Adresse" / "IP address" the box writes the address of the other side. */
const IP_AFTER_LABEL = /\bIP(?:-Adresse| address)?\s+([0-9a-f:.]+)/i;
const IP_CANDIDATE = /[0-9a-f]*:[0-9a-f:.]*(?:%\w+)?/gi;

/** Event ids seen on FRITZ!OS 8. They win over the text rules, which stay as fallback. */
const EVENT_KINDS: Record<number, EventKind> = {
    500: 'login-ok',
    504: 'login-ok',
    506: 'login-ok',
    705: 'wlan-failed',
    503: 'login-failed',
    505: 'login-failed',
    510: 'login-failed',
    502: 'settings-changed',
    2018: 'port-added',
};

const REPEAT = /\s*\[(\d+) (?:Meldungen seit|messages since)[^\]]*\]\s*$/i;
const SETTINGS = /einstellungen wurden .*geändert|settings (were|have been) changed/i;
const PORT_ADDED = /freigabe .*port.*(hinzugefügt|eingerichtet)|port (sharing|forwarding).*(added|created)/i;

const LOGIN = /\b(anmeldung|angemeldet|login|log-in|logged in|sign[- ]?in)\b/i;
const FAILED =
    /\b(gescheitert|fehlgeschlagen|ungültig|abgelehnt|nicht erfolgreich|failed|unsuccessful|not successful|invalid|denied|wrong password|falsches kennwort)\b/i;
/** Logins to the internet provider, the WLAN or for telephony are not logins to the box. */
const NOT_BOX_LOGIN =
    /wlan-anmeldung|wlan-gerät|wi-?fi (device|login)|internetanbieter|internet ?provider|\bppp\b|\bdsl\b|rufnummer|telefonie|telephony|voip|\bsip\b|registrierung|registration/i;
/** "WLAN-Gerät Anmeldung gescheitert (2,4 GHz): ungültiger WLAN-Schlüssel. MAC-Adresse: ..." */
const WLAN_FAILED =
    /wlan-gerät anmeldung gescheitert|wlan-anmeldung .*ungültiger wlan-schlüssel|wi-?fi device (login|logon|sign[- ]?in) (failed|unsuccessful)|invalid wi-?fi (key|password)/i;
const MAC_ADDR = /\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b/i;
const BLOCKED = /\b(gesperrt|sperre|blocked|locked)\b/i;
const NEW_DEVICE = /\b(neues?|new)\b.*\b(gerät|geräte|device|wlan-gerät)\b|erstmalig/i;
const VPN = /\b(vpn|wireguard|ipsec)\b/i;
const FIRMWARE = /\b(fritz!os|firmware)\b.*\b(aktualisiert|update|updated|installiert|installed)\b/i;

function toDate(d: number, mo: number, y: number, h: number, mi: number, s: number): Date | undefined {
    const year = y < 100 ? 2000 + y : y;
    const date = new Date(year, mo - 1, d, h, mi, s);
    return Number.isNaN(date.getTime()) ? undefined : date;
}

function detectChannel(msg: string): LoginChannel {
    const m = msg.toLowerCase();
    if (m.includes('tr-064') || m.includes('tr064')) {
        return 'tr064';
    }
    if (
        m.includes('myfritz') ||
        m.includes('https') ||
        m.includes('internet') ||
        m.includes('fernzugang') ||
        m.includes('remote')
    ) {
        return 'remote';
    }
    if (m.includes('app')) {
        return 'app';
    }
    if (m.includes('ftp')) {
        return 'ftp';
    }
    if (m.includes('smb') || m.includes('nas')) {
        return 'smb';
    }
    if (VPN.test(msg)) {
        return 'vpn';
    }
    if (m.includes('benutzeroberfläche') || m.includes('user interface') || m.includes('oberfläche')) {
        return 'ui';
    }
    return 'unknown';
}

function extractUser(msg: string): string | undefined {
    const m =
        /(?:benutzers|benutzerin|benutzer|users?)\s+["'„“]?([^\s"'„“,]+?)["'„“]?(?=[\s,.]|$)/i.exec(msg) ??
        /(?:username|user name|kontos?)\s+["'„“]?([^\s"'„“,]+)/i.exec(msg);
    const u = m?.[1];
    if (!u || /^(an|der|die|des|von|from|to|at|via|über)$/i.test(u)) {
        return undefined;
    }
    return u;
}

const validIp = (s: string | undefined): string | undefined => {
    const ip = s?.replace(/%\w+$/, '').replace(/[.:]+$/, '');
    return ip && isIP(ip) ? ip : undefined;
};

function extractIp(message: string): string | undefined {
    // the repeat note carries a time ("seit 10.10.26 07:00:00"), not an address
    const msg = message.replace(REPEAT, '');
    const labelled = validIp(IP_AFTER_LABEL.exec(msg)?.[1]);
    if (labelled) {
        return labelled;
    }
    const v4 = IPV4.exec(msg);
    if (v4 && isIP(v4[1])) {
        return v4[1];
    }
    // isIP drops MAC addresses and times, which look similar
    for (const m of msg.matchAll(IP_CANDIDATE)) {
        const ip = validIp(m[0]);
        if (ip) {
            return ip;
        }
    }
    return undefined;
}

export function classify(message: string): Pick<LogEvent, 'kind' | 'ip' | 'user' | 'channel' | 'reason' | 'mac'> {
    if (WLAN_FAILED.test(message)) {
        // "(2,4 GHz): ungültiger WLAN-Schlüssel. MAC-Adresse: ..." -> "ungültiger WLAN-Schlüssel"
        const why = /\)\s*:\s*([^.]{3,80})/.exec(message)?.[1]?.trim();
        return { kind: 'wlan-failed', mac: MAC_ADDR.exec(message)?.[1]?.toLowerCase(), reason: why };
    }
    const ip = extractIp(message);
    const reason = /\(([^)]{3,80})\)\.?\s*$/.exec(message.replace(REPEAT, ''))?.[1];
    if (SETTINGS.test(message)) {
        return { kind: 'settings-changed', ip };
    }
    if (PORT_ADDED.test(message)) {
        return { kind: 'port-added', ip };
    }
    // "Neues WLAN-Gerät erstmalig angemeldet" is a device, not a user login
    if (NEW_DEVICE.test(message) && !/benutzer|user/i.test(message)) {
        return { kind: 'new-device', ip };
    }
    if ((LOGIN.test(message) || /kennwort|password/i.test(message)) && !NOT_BOX_LOGIN.test(message)) {
        const base = { ip, user: extractUser(message), channel: detectChannel(message), reason };
        if (BLOCKED.test(message) && !FAILED.test(message)) {
            return { kind: 'login-blocked', ...base };
        }
        if (FAILED.test(message)) {
            return { kind: 'login-failed', ...base };
        }
        if (LOGIN.test(message)) {
            return { kind: 'login-ok', ...base };
        }
    }
    if (NEW_DEVICE.test(message)) {
        return { kind: 'new-device', ip };
    }
    if (VPN.test(message)) {
        return { kind: 'vpn', ip, user: extractUser(message) };
    }
    if (FIRMWARE.test(message)) {
        return { kind: 'firmware' };
    }
    return { kind: 'other', ip };
}

/**
 * Parses the text returned by GetDeviceLog (one event per line, newest first).
 */
export function parseDeviceLog(text: string): LogEvent[] {
    const events: LogEvent[] = [];
    for (const raw of text.split(/\r?\n/)) {
        const line = raw.trim();
        if (!line) {
            continue;
        }
        let time: Date | undefined;
        let rawTime = '';
        let message = line;
        const m = LINE.exec(line);
        const iso = m ? null : LINE_ISO.exec(line);
        if (m) {
            time = toDate(+m[1], +m[2], +m[3], +m[4], +m[5], +m[6]);
            rawTime = line.slice(0, line.length - m[7].length).trim();
            message = m[7].trim();
        } else if (iso) {
            time = toDate(+iso[3], +iso[2], +iso[1], +iso[4], +iso[5], +iso[6]);
            rawTime = line.slice(0, line.length - iso[7].length).trim();
            message = iso[7].trim();
        }
        const id = lineId(rawTime.replace(/\s+/g, ' '), message);
        events.push({
            id,
            key: eventKey(message),
            time,
            rawTime,
            message,
            count: repeatCount(message),
            ...classify(message),
        });
    }
    return events;
}

function repeatCount(message: string): number {
    const n = Number(REPEAT.exec(message)?.[1]);
    return n > 1 ? n : 1;
}

function lineId(rawTime: string, message: string): string {
    return createHash('sha1').update(`${rawTime}|${message}`).digest('hex').slice(0, 16);
}

/** Only the text: the XML log and the GetDeviceLog fallback must give the same key. */
function eventKey(message: string): string {
    return createHash('sha1').update(message.replace(REPEAT, '')).digest('hex').slice(0, 16);
}

/** What was seen of an event text: its times (ms) and the highest repeat count. */
export type SeenEvents = Record<string, { ts: number[]; n: number }>;

/** Same text this close together counts as the same entry (the box shifts times by a second now and then). */
const SAME_ENTRY_MS = 2 * 60 * 1000;

/**
 * Picks the events not reported yet. Matching by exact time does not work: the box reports
 * the same entry with a time one second off from one read to the next, and the repeat
 * counter changes the text. So an event is new when its text was not seen, when it shows up
 * again clearly later, or when its repeat counter went up.
 */
export function freshEvents(events: LogEvent[], seen: SeenEvents): { fresh: LogEvent[]; seen: SeenEvents } {
    const next: SeenEvents = {};
    const fresh: LogEvent[] = [];
    for (const e of events) {
        const t = e.time?.getTime();
        const prev = seen[e.key];
        const isNew =
            !prev || e.count > prev.n || (t !== undefined && !prev.ts.some(x => Math.abs(t - x) <= SAME_ENTRY_MS));
        if (isNew) {
            fresh.push(e);
        }
        const cur = (next[e.key] ??= { ts: [], n: 0 });
        cur.n = Math.max(cur.n, e.count);
        if (t !== undefined) {
            cur.ts.push(t);
        }
    }
    return { fresh, seen: next };
}

/**
 * Parses the XML log from X_AVM-DE_GetDeviceLogPath. Unlike GetDeviceLog it also contains
 * the system events (logins) and carries event ids and groups.
 */
export function parseDeviceLogXml(xml: string): LogEvent[] {
    const list = parseXml(xml)?.DeviceLog?.Event;
    const arr: any[] = list === undefined ? [] : Array.isArray(list) ? list : [list];
    const events: LogEvent[] = [];
    for (const e of arr) {
        const message = typeof e?.msg === 'string' ? e.msg.trim() : '';
        if (!message) {
            continue;
        }
        const rawTime = `${String(e.date ?? '')} ${String(e.time ?? '')}`.trim();
        const m = /^(\d{1,2})\.(\d{1,2})\.(\d{2,4}) (\d{1,2}):(\d{2}):(\d{2})$/.exec(rawTime);
        const eventId = Number(e.id) || undefined;
        const group = e.group ? String(e.group) : undefined;
        const c = classify(message);
        let kind = (eventId && EVENT_KINDS[eventId]) || c.kind;
        // logins to the box are system events, the same words in other groups (fon, net, wlan) mean something else
        if (group && group !== 'sys' && kind.startsWith('login')) {
            kind = 'other';
        }
        events.push({
            id: lineId(rawTime, message),
            key: eventKey(message),
            time: m ? toDate(+m[1], +m[2], +m[3], +m[4], +m[5], +m[6]) : undefined,
            rawTime,
            message,
            eventId,
            group,
            count: repeatCount(message),
            ...c,
            kind,
            // the event id also catches Wi-Fi messages in other languages, the text rule may not
            mac: c.mac ?? (kind === 'wlan-failed' ? MAC_ADDR.exec(message)?.[1]?.toLowerCase() : undefined),
        });
    }
    return events;
}
