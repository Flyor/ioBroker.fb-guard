import * as https from 'node:https';
import type { Finding } from '../findings';
import { type CheckContext, L, isOn, tryCall } from './common';

export interface FirmwareInfo {
    model: string;
    installed: string;
    uptime?: number;
    updateAvailable: boolean;
    availableVersion?: string;
    autoUpdateMode?: string;
    vendorLatest?: string;
    /** "Release" for normal firmware, anything else is a lab (beta) build. */
    buildType?: string;
    labLatest?: string;
}

/**
 * "FRITZ!Box 7590 AX" -> "fritzbox-7590-ax" (folder name on the vendor download server).
 */
export function modelSlug(model: string): string {
    return model
        .toLowerCase()
        .replace(/fritz!box/g, 'fritzbox')
        .replace(/fritz!repeater/g, 'fritzwlan-repeater')
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '');
}

/**
 * "154.08.25" or "08.25" -> [8, 25]. Build numbers ("154.08.21-120343", "154.08.21,124969") are dropped.
 */
export function versionParts(v: string): number[] {
    const parts = v
        .replace(/[-,]\d+.*$/, '')
        .split(/[.\s-]+/)
        .filter(p => /^\d+$/.test(p))
        .map(Number);
    return parts.length >= 3 ? parts.slice(-2) : parts;
}

export function isNewer(candidate: string, installed: string): boolean {
    const a = versionParts(candidate);
    const b = versionParts(installed);
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
        const x = a[i] ?? 0;
        const y = b[i] ?? 0;
        if (x !== y) {
            return x > y;
        }
    }
    return false;
}

export function parseVendorInfo(text: string): string | undefined {
    return /^\s*Version\s*:\s*(?:FRITZ!OS\s*)?([\d.]+)/im.exec(text)?.[1];
}

/**
 * Lab versions with build number: "154.08.40-137237", "8.40-137237" or "154.08.21,124969" -> [8, 40, 137237].
 */
export function labParts(v: string): number[] {
    const m = /(\d+)\.(\d+)\s*[-,]\s*(\d+)\s*$/.exec(v.trim());
    return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : [...versionParts(v), 0];
}

export function isNewerLab(candidate: string, installed: string): boolean {
    const a = labParts(candidate);
    const b = labParts(installed);
    for (let i = 0; i < 3; i++) {
        if ((a[i] ?? 0) !== (b[i] ?? 0)) {
            return (a[i] ?? 0) > (b[i] ?? 0);
        }
    }
    return false;
}

/**
 * Finds the lab version of a model on the lab page, e.g. "FRITZ!Box 7590 8.40-137237 2026-10-09" -> "8.40-137237".
 * The model name must be followed directly by the version, so "7590" does not match "7590 AX".
 */
export function parseLabPage(html: string, model: string): string | undefined {
    const text = html
        .replace(/<[^>]*>/g, ' ')
        .replace(/&nbsp;/g, ' ')
        .replace(/\s+/g, ' ');
    const name = model
        .trim()
        .replace(/\s+/g, ' ')
        .replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(`(?:^|[^\\w!])${name} (\\d+\\.\\d+-\\d+) \\d{4}-\\d{2}-\\d{2}`, 'i').exec(text)?.[1];
}

function httpsGet(url: string, timeoutMs = 10_000, maxBytes = 256 * 1024): Promise<string | undefined> {
    return new Promise(resolve => {
        const opts = {
            timeout: timeoutMs,
            signal: AbortSignal.timeout(3 * timeoutMs),
            // the web shop rejects requests without a user agent
            headers: { 'User-Agent': 'ioBroker.fb-guard (+https://github.com/Flyor/ioBroker.fb-guard)' },
        };
        const req = https.get(url, opts, res => {
            if (res.statusCode !== 200) {
                res.resume();
                resolve(undefined);
                return;
            }
            let body = '';
            res.setEncoding('utf8');
            res.on('data', (c: string) => {
                body += c;
                if (body.length > maxBytes) {
                    req.destroy();
                }
            });
            // a destroyed or aborted answer never ends, settle anyway (no-op after 'end')
            res.on('close', () => resolve(undefined));
            res.on('end', () => resolve(body));
        });
        req.on('timeout', () => req.destroy());
        req.on('error', () => resolve(undefined));
        req.on('close', () => resolve(undefined));
    });
}

/**
 * Reads only the public version text file from the vendor download server, never firmware images.
 */
export async function fetchVendorLatest(model: string): Promise<string | undefined> {
    const slug = modelSlug(model);
    if (!slug) {
        return undefined;
    }
    for (const region of ['deutschland', 'other']) {
        for (const file of ['info_de.txt', 'info_en.txt']) {
            const text = await httpsGet(`https://download.avm.de/fritzbox/${slug}/${region}/fritz.os/${file}`);
            const v = text ? parseVendorInfo(text) : undefined;
            if (v) {
                return v;
            }
        }
    }
    return undefined;
}

/**
 * Reads the public lab page of the vendor, never firmware files.
 */
export async function fetchLabLatest(model: string): Promise<string | undefined> {
    const html = await httpsGet(
        'https://fritz.com/pages/fritz-labor-frisch-aus-der-entwicklung',
        15_000,
        2 * 1024 * 1024,
    );
    return html ? parseLabPage(html, model) : undefined;
}

export async function checkFirmware(
    ctx: CheckContext,
    opts: {
        vendorCheck: boolean;
        ageDays: (id: string) => number;
    },
): Promise<{
    info: FirmwareInfo;
    findings: Finding[];
}> {
    const { lang } = ctx;
    const dev = await tryCall(ctx, 'DeviceInfo:1', 'GetInfo');
    const ui = await tryCall(ctx, 'UserInterface:1', 'GetInfo');
    // FRITZ!OS 8 reports the auto update mode only here
    const uiEx = await tryCall(ctx, 'UserInterface:1', 'X_AVM-DE_GetInfo');
    const model = dev?.NewModelName || ctx.client.device?.modelName || '';
    const installed = dev?.NewSoftwareVersion || ctx.client.device?.firmware || '';
    const info: FirmwareInfo = {
        model,
        installed,
        uptime: dev?.NewUpTime ? Number(dev.NewUpTime) : undefined,
        updateAvailable: isOn(ui?.NewUpgradeAvailable),
        availableVersion: ui?.['NewX_AVM-DE_Version'] || undefined,
        autoUpdateMode: uiEx?.['NewX_AVM-DE_AutoUpdateMode'] || ui?.['NewX_AVM-DE_AutoUpdateMode'] || undefined,
        buildType: ui?.['NewX_AVM-DE_BuildType'] || undefined,
    };
    const isLab = !!info.buildType && !/^release$/i.test(info.buildType);
    const findings: Finding[] = [];

    if (info.updateAvailable) {
        const id = `firmware:update:${info.availableVersion ?? 'new'}`;
        const days = opts.ageDays(id);
        findings.push({
            id,
            category: 'firmware',
            severity: days >= 14 ? 'critical' : 'warning',
            title: L(lang, 'FRITZ!OS-Update verfügbar', 'FRITZ!OS update available'),
            // the day count must stay out of the detail: that text is hashed, it would report the update every day
            detail: L(
                lang,
                `Installiert ist ${installed}, verfügbar ist ${info.availableVersion ?? 'eine neuere Version'}.${days >= 14 ? ' Das Update liegt seit mehr als zwei Wochen bereit.' : ''}`,
                `Installed: ${installed}, available: ${info.availableVersion ?? 'a newer version'}.${days >= 14 ? ' Waiting for more than two weeks.' : ''}`,
            ),
            advice: L(
                lang,
                `Unter System > Update installieren. Updates schließen oft Sicherheitslücken.${days >= 1 ? ` Das Update liegt seit ${days} Tagen bereit.` : ''}`,
                `Install it under System > Update. Updates often fix security holes.${days >= 1 ? ` Waiting for ${days} days.` : ''}`,
            ),
        });
    }

    if (info.autoUpdateMode && /^(off|check|none|0)$/i.test(info.autoUpdateMode)) {
        findings.push({
            id: 'firmware:autoupdate-off',
            category: 'firmware',
            severity: 'info',
            title: L(lang, 'Automatische Updates sind aus', 'Automatic updates are off'),
            detail: L(
                lang,
                'Die Box installiert Sicherheitsupdates nicht selbst.',
                'The box does not install security updates by itself.',
            ),
            advice: L(
                lang,
                'Unter System > Update > Auto-Update mindestens wichtige Updates automatisch installieren lassen.',
                'Under System > Update > Auto-Update, at least install important updates automatically.',
            ),
            ackable: true,
        });
    }

    if (isLab) {
        findings.push({
            id: 'firmware:lab',
            category: 'firmware',
            severity: 'info',
            title: L(lang, 'Labor-Firmware installiert', 'Lab firmware installed'),
            detail: L(
                lang,
                `Auf der Box läuft eine Labor-Version (${installed}). Labor-Versionen sind Testversionen und können Fehler haben, auch Sicherheitsfehler.`,
                `The box runs a lab version (${installed}). Lab versions are test builds and may contain bugs, including security bugs.`,
            ),
            advice: L(
                lang,
                'Wenn du das bewusst nutzt, hier bestätigen. Labor-Versionen regelmäßig aktualisieren oder zurück auf die normale Version wechseln.',
                'If you use it on purpose, confirm it here. Keep lab versions up to date or switch back to the normal version.',
            ),
            ackable: true,
        });
    }

    if (opts.vendorCheck && model && isLab) {
        info.labLatest = await fetchLabLatest(model);
        if (info.labLatest && installed && isNewerLab(info.labLatest, installed) && !info.updateAvailable) {
            findings.push({
                id: `firmware:lab:${info.labLatest}`,
                category: 'firmware',
                severity: 'warning',
                title: L(lang, 'Neuere Labor-Version verfügbar', 'Newer lab version available'),
                detail: L(
                    lang,
                    `Auf der Labor-Seite des Herstellers gibt es ${info.labLatest}, installiert ist ${installed}.`,
                    `The vendor lab page offers ${info.labLatest}, installed is ${installed}.`,
                ),
                advice: L(
                    lang,
                    'Labor-Versionen bekommen Fehlerbehebungen nur über neuere Labor-Versionen. Unter System > Update oder von der Labor-Seite aktualisieren.',
                    'Lab versions only get fixes through newer lab versions. Update under System > Update or from the lab page.',
                ),
            });
        }
    }

    if (opts.vendorCheck && model) {
        info.vendorLatest = await fetchVendorLatest(model);
        if (info.vendorLatest && installed && isNewer(info.vendorLatest, installed) && !info.updateAvailable) {
            findings.push({
                id: `firmware:vendor:${info.vendorLatest}`,
                category: 'firmware',
                severity: 'warning',
                title: L(lang, 'Neuere Firmware beim Hersteller', 'Newer firmware on the vendor server'),
                detail: L(
                    lang,
                    `Auf dem Download-Server liegt FRITZ!OS ${info.vendorLatest}, installiert ist ${installed}. Die Box selbst meldet noch kein Update (z. B. bei Provider-Boxen oder gestaffelter Verteilung).`,
                    `The download server offers FRITZ!OS ${info.vendorLatest}, installed is ${installed}. The box itself does not report an update yet (e.g. ISP-branded boxes or staged rollout).`,
                ),
            });
        }
    }
    return { info, findings };
}
