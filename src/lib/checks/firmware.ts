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
 * "154.08.25" or "08.25" -> [8, 25]
 */
export function versionParts(v: string): number[] {
    const parts = v
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
    return /^\s*Version\s*:\s*([\d.]+)/im.exec(text)?.[1];
}

function httpsGet(url: string, timeoutMs = 10_000): Promise<string | undefined> {
    return new Promise(resolve => {
        const req = https.get(url, { timeout: timeoutMs, signal: AbortSignal.timeout(3 * timeoutMs) }, res => {
            if (res.statusCode !== 200) {
                res.resume();
                resolve(undefined);
                return;
            }
            let body = '';
            res.setEncoding('utf8');
            res.on('data', (c: string) => {
                body += c;
                if (body.length > 256 * 1024) {
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
    };
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
