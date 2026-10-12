import type { Finding } from '../findings';
import { parseXml } from '../tr064/soap';
import { type CheckContext, L, isOn, tryCall } from './common';

export function parseUserList(xml: string): string[] {
    if (!xml) {
        return [];
    }
    const doc = parseXml(xml);
    const list = doc?.List?.Username;
    const arr = list === undefined ? [] : Array.isArray(list) ? list : [list];
    return arr.map(u => String(typeof u === 'object' ? (u['#text'] ?? '') : u)).filter(Boolean);
}

/**
 * True if the rights list of X_AVM-DE_GetCurrentUser grants at least read access to the box settings.
 * Each path is paired with its own access value, so a right of another area cannot count.
 */
export function hasSettingsRight(rights: string): boolean {
    const pairs = [...rights.matchAll(/<path>\s*([^<]*?)\s*<\/path>\s*<access>\s*([^<]*?)\s*<\/access>/gi)];
    if (pairs.length) {
        return pairs.some(([, path, access]) => /^boxadmin$/i.test(path) && /^read(write|only)$/i.test(access));
    }
    return /einstellungen/i.test(rights);
}

export interface SettingsResult {
    findings: Finding[];
    /** Undefined if the box did not hand out the user list, so it must not become the baseline. */
    users?: string[];
}

/**
 * Checks login and WLAN related settings.
 *
 * @param ctx check context
 * @param knownUsers users seen on the first run (baseline); new ones raise an alarm
 * @param ownUser the user this adapter logs in with
 */
export async function checkSettings(
    ctx: CheckContext,
    knownUsers: string[] | undefined,
    ownUser: string,
): Promise<SettingsResult> {
    const { lang } = ctx;
    const findings: Finding[] = [];

    const sec = await tryCall(ctx, 'LANConfigSecurity:1', 'GetInfo');
    if (isOn(sec?.['NewX_AVM-DE_IsDefaultPasswordActive'])) {
        findings.push({
            id: 'login:default-password',
            category: 'settings',
            severity: 'critical',
            title: L(lang, 'Werkseitiges Kennwort ist aktiv', 'Factory password is active'),
            detail: L(
                lang,
                'Die Box nutzt noch das Kennwort vom Aufkleber.',
                'The box still uses the password printed on the label.',
            ),
            advice: L(
                lang,
                'Unter System > FRITZ!Box-Benutzer ein eigenes, langes Kennwort setzen.',
                'Set your own long password under System > FRITZ!Box Users.',
            ),
        });
    }

    const anon = await tryCall(ctx, 'LANConfigSecurity:1', 'X_AVM-DE_GetAnonymousLogin');
    if (isOn(anon?.['NewX_AVM-DE_AnonymousLoginEnabled'])) {
        findings.push({
            id: 'login:anonymous',
            category: 'settings',
            severity: 'critical',
            title: L(lang, 'Anmeldung ohne Kennwort möglich', 'Login without password possible'),
            detail: L(
                lang,
                'Jeder im Heimnetz kann die Box ohne Kennwort bedienen.',
                'Anyone on the home network can use the box without a password.',
            ),
            advice: L(
                lang,
                'Unter System > FRITZ!Box-Benutzer > Anmeldung im Heimnetz eine Anmeldung mit Kennwort erzwingen.',
                'Require a password under System > FRITZ!Box Users > Login.',
            ),
        });
    }

    const auth = await tryCall(ctx, 'X_AVM-DE_Auth:1', 'GetInfo');
    if (auth && !isOn(auth.NewEnabled)) {
        findings.push({
            id: 'login:2fa-off',
            category: 'settings',
            severity: 'warning',
            title: L(lang, 'Zweiter Faktor ist aus', 'Two-factor confirmation is off'),
            detail: L(
                lang,
                'Wichtige Änderungen an der Box werden nicht zusätzlich bestätigt (Taste an der Box, Telefon oder Authenticator-App).',
                'Important changes are not confirmed by a second factor (button on the box, phone or authenticator app).',
            ),
            advice: L(
                lang,
                'Unter System > FRITZ!Box-Benutzer > Anmeldung im Heimnetz die Zwei-Faktor-Authentifizierung einschalten.',
                'Enable two-factor authentication under System > FRITZ!Box Users.',
            ),
            ackable: true,
        });
    }

    const ul = await tryCall(ctx, 'LANConfigSecurity:1', 'X_AVM-DE_GetUserList');
    const users = ul ? parseUserList(ul['NewX_AVM-DE_UserList'] ?? '') : undefined;
    for (const u of users ?? []) {
        if (u === ownUser) {
            continue;
        }
        const isNew = knownUsers !== undefined && !knownUsers.includes(u);
        findings.push({
            id: `user:${u}`,
            category: 'settings',
            severity: isNew ? 'critical' : 'info',
            title: isNew
                ? L(lang, `Neuer FRITZ!Box-Benutzer "${u}"`, `New FRITZ!Box user "${u}"`)
                : L(lang, `FRITZ!Box-Benutzer "${u}"`, `FRITZ!Box user "${u}"`),
            detail: isNew
                ? L(
                      lang,
                      'Dieser Benutzer ist neu angelegt worden. Wenn du das nicht warst, ist das ein Alarmzeichen.',
                      'This user was just created. If it was not you, this is a red flag.',
                  )
                : L(
                      lang,
                      'Hat Zugang zur Box. Unbenutzte Benutzer sind ein unnötiges Risiko.',
                      'Has access to the box. Unused accounts are an unnecessary risk.',
                  ),
            advice: L(
                lang,
                'Wenn du den Benutzer nicht brauchst: unter System > FRITZ!Box-Benutzer löschen. Sonst bestätigen.',
                'If you do not need it, delete it under System > FRITZ!Box Users. Otherwise confirm it.',
            ),
            more: L(
                lang,
                'Wie kritisch ein Benutzer ist, hängt von seinen Rechten ab. Die verrät die Box über ihre Schnittstelle nicht, bitte selbst nachsehen:\n• Nur Smart Home: kann Geräte schalten (Steckdosen, Heizung), aber nichts an der Box einstellen. Eher gering.\n• Nur NAS: Zugriff auf die Dateien im Box-Speicher. Gering bis mittel, je nach Inhalt.\n• FRITZ!Box Einstellungen: voller Zugriff auf die Box. Hoch.\nIn jedem Fall kritischer, wenn "Zugang auch aus dem Internet" an ist oder das Kennwort schwach ist. Unbenutzte Konten trotzdem löschen, jedes ist ein weiteres Kennwort, das jemand erraten kann.',
                'How critical a user is depends on its rights. The box does not report them through its interface, please check yourself:\n• Smart home only: can switch devices (sockets, heating) but not change the box. Rather low.\n• NAS only: access to files on the box storage. Low to medium, depending on the content.\n• FRITZ!Box settings: full access to the box. High.\nIn any case more critical if "access from the internet" is on or the password is weak. Still delete unused accounts, each one is another password someone can guess.',
            ),
            ackable: true,
        });
    }

    for (let i = 1; i <= 4; i++) {
        const svc = `WLANConfiguration:${i}`;
        const w = await tryCall(ctx, svc, 'GetInfo');
        if (!w || !isOn(w.NewEnable)) {
            continue;
        }
        const ssid = w.NewSSID || `WLAN ${i}`;
        const beacon = (w.NewBeaconType || '').toLowerCase();
        if (beacon === 'none' || beacon === 'basic') {
            findings.push({
                id: `wlan:${i}:weak`,
                category: 'settings',
                severity: beacon === 'none' ? 'warning' : 'critical',
                title:
                    beacon === 'none'
                        ? L(lang, `WLAN "${ssid}" ist offen`, `WLAN "${ssid}" is open`)
                        : L(lang, `WLAN "${ssid}" nutzt WEP`, `WLAN "${ssid}" uses WEP`),
                detail:
                    beacon === 'none'
                        ? L(
                              lang,
                              'Jeder in Reichweite kann sich verbinden. Bei einem bewusst offenen Gast-Hotspot bestätigen.',
                              'Anyone in range can connect. Confirm if this is an intended guest hotspot.',
                          )
                        : L(lang, 'WEP lässt sich in Minuten knacken.', 'WEP can be cracked in minutes.'),
                advice: L(
                    lang,
                    'Unter WLAN > Sicherheit WPA2 + WPA3 einstellen.',
                    'Set WPA2 + WPA3 under Wi-Fi > Security.',
                ),
                ackable: beacon === 'none',
            });
        } else if (beacon === 'wpa') {
            findings.push({
                id: `wlan:${i}:wpa1`,
                category: 'settings',
                severity: 'warning',
                title: L(lang, `WLAN "${ssid}" nutzt nur WPA`, `WLAN "${ssid}" uses WPA only`),
                detail: L(lang, 'WPA (Version 1) gilt als veraltet.', 'WPA (version 1) is outdated.'),
                advice: L(
                    lang,
                    'Unter WLAN > Sicherheit WPA2 + WPA3 einstellen.',
                    'Set WPA2 + WPA3 under Wi-Fi > Security.',
                ),
            });
        }
        if (i === 1) {
            const wps = await tryCall(ctx, svc, 'X_AVM-DE_GetWPSInfo');
            const mode = (wps?.['NewX_AVM-DE_WPSMode'] || '').toLowerCase();
            if (mode && !['stop', 'off', 'disabled'].includes(mode)) {
                findings.push({
                    id: 'wlan:wps',
                    category: 'settings',
                    severity: 'info',
                    title: L(lang, 'WPS ist aktiv', 'WPS is active'),
                    detail: L(
                        lang,
                        'Geräte können sich gerade per Knopfdruck/PIN verbinden.',
                        'Devices can currently connect via push button/PIN.',
                    ),
                    ackable: true,
                });
            }
        }
    }

    return { findings, users };
}
