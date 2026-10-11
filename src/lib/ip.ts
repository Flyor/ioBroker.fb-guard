import { isIP } from 'node:net';

export type IpScope = 'private' | 'loopback' | 'linklocal' | 'cgnat' | 'public' | 'invalid';

function v4ToInt(ip: string): number {
    return ip.split('.').reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0;
}

function inV4(ip: string, cidr: string): boolean {
    const [net, bits] = cidr.split('/');
    const mask = bits === '0' ? 0 : (~0 << (32 - Number(bits))) >>> 0;
    return (v4ToInt(ip) & mask) === (v4ToInt(net) & mask);
}

/** Expands an IPv6 address into its 8 groups. */
function v6Groups(ip: string): number[] {
    let s = ip.toLowerCase().replace(/%\w+$/, '');
    const v4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
    if (v4) {
        const n = v4ToInt(v4[1]);
        s = `${s.slice(0, -v4[1].length)}${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`;
    }
    const [head, tail] = s.split('::');
    const a = head ? head.split(':') : [];
    const b = tail !== undefined && tail !== '' ? tail.split(':') : [];
    const fill = tail === undefined ? [] : Array<string>(8 - a.length - b.length).fill('0');
    return [...a, ...fill, ...b].map(g => parseInt(g, 16) || 0);
}

/**
 * Global IPv6 prefixes of the home network. A FRITZ!Box hands out global addresses in the LAN,
 * so without this every IPv6 login from home would look like it came from the internet.
 */
let homeV6: number[][] = [];

/**
 * Learns the home network prefixes from the global IPv6 addresses of this host. The box gets
 * at least a /56 from the provider, the guest network sits in the same block.
 *
 * @param addresses IPv6 addresses of this host
 */
export function learnHomeIpv6(addresses: string[]): void {
    homeV6 = [];
    homeV6 = addresses
        .filter(a => isIP(a) === 6 && classifyIp(a) === 'public')
        .map(a =>
            v6Groups(a)
                .slice(0, 4)
                .map((g, i) => (i === 3 ? g & 0xff00 : g)),
        );
}

function inHomeV6(ip: string): boolean {
    const g = v6Groups(ip);
    return homeV6.some(p => p[0] === g[0] && p[1] === g[1] && p[2] === g[2] && p[3] === (g[3] & 0xff00));
}

/**
 * Classifies an address without any network lookup.
 */
export function classifyIp(ip: string): IpScope {
    const v = isIP(ip);
    if (v === 4) {
        if (inV4(ip, '127.0.0.0/8')) {
            return 'loopback';
        }
        if (inV4(ip, '169.254.0.0/16')) {
            return 'linklocal';
        }
        if (inV4(ip, '10.0.0.0/8') || inV4(ip, '172.16.0.0/12') || inV4(ip, '192.168.0.0/16')) {
            return 'private';
        }
        if (inV4(ip, '100.64.0.0/10')) {
            return 'cgnat';
        }
        return 'public';
    }
    if (v === 6) {
        const lower = ip.toLowerCase();
        if (lower === '::1') {
            return 'loopback';
        }
        if (lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) {
            return 'linklocal';
        }
        if (lower.startsWith('fc') || lower.startsWith('fd')) {
            return 'private';
        }
        const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
        if (mapped) {
            return classifyIp(mapped[1]);
        }
        return inHomeV6(ip) ? 'private' : 'public';
    }
    return 'invalid';
}

export function isFromInternet(ip: string): boolean {
    return classifyIp(ip) === 'public';
}

/**
 * Parses a comma/space separated list of IPs and CIDR ranges (IPv4 CIDR only).
 */
export function parseIpList(list: string): string[] {
    return list
        .split(/[\s,;]+/)
        .map(s => s.trim())
        .filter(Boolean);
}

export function ipInList(ip: string, list: string[]): boolean {
    return list.some(entry => {
        if (entry.includes('/') && isIP(ip) === 4) {
            const [net] = entry.split('/');
            return isIP(net) === 4 && inV4(ip, entry);
        }
        return entry.toLowerCase() === ip.toLowerCase();
    });
}

export function describeScope(scope: IpScope, lang: 'de' | 'en'): string {
    const de: Record<IpScope, string> = {
        private: 'aus deinem Heimnetz',
        loopback: 'vom Gerät selbst',
        linklocal: 'aus dem lokalen Netzsegment',
        cgnat: 'aus einem Provider-Netz (CGNAT)',
        public: 'aus dem Internet',
        invalid: 'unbekannter Herkunft',
    };
    const en: Record<IpScope, string> = {
        private: 'from your home network',
        loopback: 'from the device itself',
        linklocal: 'from the local link',
        cgnat: 'from a carrier network (CGNAT)',
        public: 'from the internet',
        invalid: 'of unknown origin',
    };
    return (lang === 'de' ? de : en)[scope];
}
