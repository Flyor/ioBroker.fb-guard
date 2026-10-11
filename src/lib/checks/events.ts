import { describeScope, classifyIp, ipInList } from '../ip';
import type { Lang } from '../knowledge/ports';
import type { LogEvent } from '../logparser';
import { parseDeviceLog, parseDeviceLogXml } from '../logparser';
import { type CheckContext, L, tryCall } from './common';
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

function fmtTime(e: LogEvent, lang: Lang): string {
    return e.time ? e.time.toLocaleString(lang === 'de' ? 'de-DE' : 'en-GB') : e.rawTime || '?';
}

const channelName = (c: string | undefined, lang: Lang): string => {
    const de: Record<string, string> = {
        ui: 'Benutzeroberfläche',
        remote: 'Fernzugriff übers Internet',
        tr064: 'TR-064 (Programme/Apps)',
        app: 'App',
        ftp: 'FTP',
        smb: 'Speicher (SMB)',
        vpn: 'VPN',
        unknown: 'unbekannt',
    };
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
    return (lang === 'de' ? de : en)[c ?? 'unknown'] ?? c ?? '';
};

/**
 * Turns new log events into alerts. Failed logins are grouped per source address.
 */
export function evaluateEvents(events: LogEvent[], opts: EventOptions, lang: Lang): EventAlert[] {
    const alerts: EventAlert[] = [];
    const failed = new Map<string, LogEvent[]>();

    for (const e of events) {
        if (e.kind === 'login-failed' || e.kind === 'login-blocked') {
            const key = e.ip ?? '?';
            failed.set(key, [...(failed.get(key) ?? []), e]);
        } else if (e.kind === 'login-ok' && opts.alertRemoteLogins && e.ip) {
            if (e.user && e.user === opts.ownUser) {
                continue;
            }
            if (classifyIp(e.ip) === 'public' && !ipInList(e.ip, opts.knownIps)) {
                alerts.push({
                    severity: 'warning',
                    title: L(lang, 'Anmeldung aus dem Internet', 'Login from the internet'),
                    text: L(
                        lang,
                        `${fmtTime(e, lang)}: ${e.user ? `Benutzer "${e.user}"` : 'Ein Benutzer'} hat sich von ${e.ip} angemeldet (${channelName(e.channel, lang)}). Warst du das nicht, sofort das Kennwort ändern.\n\n${e.message}`,
                        `${fmtTime(e, lang)}: ${e.user ? `user "${e.user}"` : 'a user'} logged in from ${e.ip} (${channelName(e.channel, lang)}). If this was not you, change the password right away.\n\n${e.message}`,
                    ),
                });
            }
        } else if (e.kind === 'port-added') {
            alerts.push({
                severity: 'warning',
                title: L(lang, 'Neue Portfreigabe', 'New port forwarding'),
                text: L(
                    lang,
                    `${fmtTime(e, lang)}: ${e.message}

War das gewollt? Wenn nicht, die Freigabe in der Box löschen.`,
                    `${fmtTime(e, lang)}: ${e.message}

Was this intended? If not, delete the forwarding in the box.`,
                ),
            });
        } else if (e.kind === 'settings-changed') {
            alerts.push({
                severity: 'info',
                title: L(lang, 'Einstellungen geändert', 'Settings changed'),
                text: `${fmtTime(e, lang)}: ${e.message}`,
            });
        } else if (e.kind === 'new-device' && opts.alertNewDevices) {
            const d = deviceFromMessage(e.message);
            if (opts.skipKnownPrivate && opts.hosts && isKnownWithNewAddress(opts.hosts, d.mac, d.name)) {
                continue;
            }
            const hint = isRandomMac(d.mac)
                ? L(
                      lang,
                      '\n\nDas Gerät nutzt eine private (wechselnde) Adresse, z. B. iPhone, Android oder Windows. Es kann ein bekanntes Gerät mit neuer Adresse sein.',
                      '\n\nThe device uses a private (changing) address, e.g. iPhone, Android or Windows. It may be a known device with a new address.',
                  )
                : '';
            alerts.push({
                severity: 'info',
                title: L(lang, 'Neues Gerät im Netz', 'New device on the network'),
                text: `${fmtTime(e, lang)}: ${e.message}${hint}`,
            });
        }
    }

    for (const [ip, list] of failed) {
        const scope = ip === '?' ? 'invalid' : classifyIp(ip);
        const users = [...new Set(list.map(e => e.user).filter(Boolean))];
        const channels = [...new Set(list.map(e => channelName(e.channel, lang)))];
        const times = list.map(e => e.time?.getTime()).filter((t): t is number => t !== undefined);
        const first = list.reduce((a, b) => ((a.time?.getTime() ?? 0) < (b.time?.getTime() ?? 0) ? a : b));
        const last = list.reduce((a, b) => ((a.time?.getTime() ?? 0) > (b.time?.getTime() ?? 0) ? a : b));
        const count = list.reduce((n, e) => n + e.count, 0);
        const attack = count >= opts.attackThreshold;
        // 503 = old browser tab with an expired session, not a password guess
        const staleOnly = list.every(e => e.eventId === 503);
        const severity = scope === 'public' || attack ? 'critical' : staleOnly ? 'info' : 'warning';
        const span = times.length > 1 ? `${fmtTime(first, lang)} – ${fmtTime(last, lang)}` : fmtTime(last, lang);

        const lines = [
            L(lang, `Anzahl: ${count}`, `Count: ${count}`),
            L(lang, `Zeit: ${span}`, `Time: ${span}`),
            L(lang, `Von: ${ip} (${describeScope(scope, 'de')})`, `From: ${ip} (${describeScope(scope, 'en')})`),
            L(lang, `Zugang: ${channels.join(', ')}`, `Access: ${channels.join(', ')}`),
        ];
        if (users.length) {
            lines.push(L(lang, `Benutzername: ${users.join(', ')}`, `User name: ${users.join(', ')}`));
        }
        if (last.reason) {
            lines.push(L(lang, `Grund: ${last.reason}`, `Reason: ${last.reason}`));
        }
        lines.push(
            '',
            scope === 'public'
                ? L(
                      lang,
                      'Jemand aus dem Internet probiert Kennwörter aus. Die Box bremst das aus. Wenn du den Fernzugriff nicht brauchst, schalte ihn ab.',
                      'Someone on the internet is guessing passwords. The box slows this down. If you do not need remote access, turn it off.',
                  )
                : staleOnly
                  ? L(
                        lang,
                        'Meist ein alter Browser-Tab der Box-Oberfläche mit abgelaufener Sitzung. Tab schließen oder neu laden.',
                        'Usually an old browser tab of the box interface with an expired session. Close or reload it.',
                    )
                  : L(
                        lang,
                        'Der Versuch kam aus deinem Heimnetz. Meist ein vertipptes Kennwort oder ein Gerät/Programm mit altem Kennwort.',
                        'The attempt came from your home network. Usually a typo or a device/program with an old password.',
                    ),
        );
        alerts.push({
            severity,
            title: attack
                ? L(lang, 'Mehrere fehlgeschlagene Anmeldungen', 'Multiple failed logins')
                : L(lang, 'Fehlgeschlagene Anmeldung', 'Failed login'),
            text: lines.join('\n'),
        });
    }
    return alerts;
}
