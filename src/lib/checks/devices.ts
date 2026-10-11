import { parseXml } from '../tr064/soap';
import type { Lang } from '../knowledge/ports';
import { type CheckContext, L, isOn, tryCall } from './common';

export interface Host {
    mac: string;
    ip?: string;
    name?: string;
    active: boolean;
    iface?: string;
}

const MAC = /\b([0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})\b/i;
const MAX_HOSTS = 500;

/**
 * True for "private" or randomized addresses (locally administered bit set).
 * Phones, tablets and laptops use them to avoid tracking; they can change per network or over time.
 */
export function isRandomMac(mac: string | undefined): boolean {
    const m = mac?.trim().toLowerCase();
    if (!m || !MAC.test(m)) {
        return false;
    }
    return (parseInt(m.slice(0, 2), 16) & 0x02) === 0x02;
}

const normName = (n?: string): string =>
    (n ?? '')
        .toLowerCase()
        .replace(/\.(fritz\.box|local|lan|home)$/, '')
        .trim();

/**
 * Parses the host list from Hosts X_AVM-DE_GetHostListPath.
 */
export function parseHostListXml(xml: string): Host[] {
    const items = parseXml(xml)?.List?.Item;
    const arr: any[] = items === undefined ? [] : Array.isArray(items) ? items : [items];
    return arr
        .filter(i => i?.MACAddress)
        .map(i => ({
            mac: String(i.MACAddress).toLowerCase(),
            ip: i.IPAddress ? String(i.IPAddress) : undefined,
            name: i.HostName ? String(i.HostName) : undefined,
            active: isOn(String(i.Active ?? '')),
            iface: i.InterfaceType ? String(i.InterfaceType) : undefined,
        }));
}

/**
 * Reads all devices the box knows (active and inactive).
 */
export async function readHosts(ctx: CheckContext): Promise<Host[] | undefined> {
    const p = await tryCall(ctx, 'Hosts:1', 'X_AVM-DE_GetHostListPath');
    if (p?.['NewX_AVM-DE_HostListPath']) {
        try {
            return parseHostListXml(await ctx.client.fetchFromBox(p['NewX_AVM-DE_HostListPath']));
        } catch (e) {
            ctx.log.debug(`Host list not readable: ${(e as Error).message}`);
        }
    }
    const n = Number((await tryCall(ctx, 'Hosts:1', 'GetHostNumberOfEntries'))?.NewHostNumberOfEntries);
    if (!n) {
        return undefined;
    }
    const hosts: Host[] = [];
    for (let i = 0; i < Math.min(n, MAX_HOSTS); i++) {
        const h = await tryCall(ctx, 'Hosts:1', 'GetGenericHostEntry', { NewIndex: i });
        if (h?.NewMACAddress) {
            hosts.push({
                mac: h.NewMACAddress.toLowerCase(),
                ip: h.NewIPAddress || undefined,
                name: h.NewHostName || undefined,
                active: isOn(h.NewActive),
                iface: h.NewInterfaceType || undefined,
            });
        }
    }
    return hosts;
}

/**
 * Pulls MAC address and device name out of a "new device" log line.
 */
export function deviceFromMessage(msg: string): { mac?: string; name?: string } {
    const mac = MAC.exec(msg)?.[1].toLowerCase().replace(/-/g, ':');
    const name =
        /\bName:?\s+"?([^",]+?)"?\s*(?:,|\)|$)/i.exec(msg)?.[1] ??
        // "..., 866 Mbit/s, iPhone-von-Max, IP 192.168.178.20, MAC ..."
        /,\s*([^,]+?),\s*IP\b/i.exec(msg)?.[1];
    return { mac, name: name?.trim() || undefined };
}

/**
 * True if the box already knows a device with this name under another address,
 * i.e. a known phone or laptop that just picked a new private address.
 */
export function isKnownWithNewAddress(hosts: Host[], mac: string | undefined, name: string | undefined): boolean {
    const n = normName(name);
    if (!n || !isRandomMac(mac)) {
        return false;
    }
    return hosts.some(h => h.mac !== mac && normName(h.name) === n);
}

/** Systems known to use private (changing) addresses. */
export function randomMacSystems(lang: Lang): string {
    return L(
        lang,
        'Betrifft vor allem iPhone, iPad, Apple Watch und Mac ("Private WLAN-Adresse"), Android ab Version 10 ("Zufällige MAC"), Windows 10/11 ("Zufällige Hardwareadressen") und Chromebooks. Je nach Einstellung wechselt die Adresse pro Netz oder regelmäßig.',
        'Mainly iPhone, iPad, Apple Watch and Mac ("Private Wi-Fi address"), Android 10 and later ("Randomized MAC"), Windows 10/11 ("Random hardware addresses") and Chromebooks. Depending on the setting the address changes per network or regularly.',
    );
}

/**
 * Short overview for the settings page: how many devices the box knows and which use private addresses.
 */
export function describeHosts(hosts: Host[] | undefined, lang: Lang): string {
    if (!hosts) {
        return L(
            lang,
            'Die Geräteliste der Box ist nicht lesbar (Recht "FRITZ!Box Einstellungen" fehlt?).',
            'The device list of the box cannot be read (right "FRITZ!Box Settings" missing?).',
        );
    }
    const random = hosts.filter(h => isRandomMac(h.mac));
    const names = [...new Set(random.map(h => h.name || '?'))].slice(0, 15);
    const lines = [
        L(
            lang,
            `Die Box kennt ${hosts.length} Geräte, ${hosts.filter(h => h.active).length} davon gerade aktiv.`,
            `The box knows ${hosts.length} devices, ${hosts.filter(h => h.active).length} of them active right now.`,
        ),
    ];
    if (random.length) {
        lines.push(
            L(
                lang,
                `${random.length} nutzen eine private (wechselnde) Adresse: ${names.join(', ')}${random.length > names.length ? ', …' : ''}. Diese können nach einem Adresswechsel erneut als "neu" auftauchen.`,
                `${random.length} use a private (changing) address: ${names.join(', ')}${random.length > names.length ? ', …' : ''}. They can show up as "new" again after an address change.`,
            ),
        );
    } else {
        lines.push(L(lang, 'Kein Gerät nutzt eine private Adresse.', 'No device uses a private address.'));
    }
    if (hosts.length <= 3) {
        lines.push(
            L(
                lang,
                'Sehr wenige Geräte: Steht ein weiterer Router hinter der Box, sieht die Box nur diesen, nicht die Geräte dahinter.',
                'Very few devices: if another router sits behind the box, the box only sees that router, not the devices behind it.',
            ),
        );
    }
    return lines.join('\n');
}
