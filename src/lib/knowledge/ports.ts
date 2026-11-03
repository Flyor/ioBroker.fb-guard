import { t } from '../i18n';

export type Risk = 'high' | 'medium' | 'low';

interface PortInfo {
    name: string;
    risk: Risk;
    text: string;
}

const tcp: Record<number, PortInfo> = {
    21: {
        name: 'FTP',
        risk: 'high',
        text: 'FTP sends passwords in clear text.',
    },
    22: {
        name: 'SSH',
        risk: 'medium',
        text: 'SSH access. Constantly hit by password-guessing bots, use key-based login only.',
    },
    23: {
        name: 'Telnet',
        risk: 'high',
        text: 'Telnet is unencrypted and should never face the internet.',
    },
    25: {
        name: 'SMTP',
        risk: 'medium',
        text: 'Mail server. Only makes sense if you really run one.',
    },
    53: {
        name: 'DNS',
        risk: 'high',
        text: 'Open DNS resolvers get abused for attacks on others.',
    },
    80: {
        name: 'HTTP',
        risk: 'medium',
        text: 'Unencrypted web server. Prefer exposing HTTPS only.',
    },
    111: {
        name: 'RPC',
        risk: 'high',
        text: 'RPC service (often NAS/NFS). Should not face the internet.',
    },
    139: {
        name: 'NetBIOS',
        risk: 'high',
        text: 'Windows file sharing. Never expose to the internet.',
    },
    443: {
        name: 'HTTPS',
        risk: 'low',
        text: 'Encrypted web server or reverse proxy.',
    },
    445: {
        name: 'SMB',
        risk: 'high',
        text: 'Windows/NAS file sharing. Common ransomware target, never expose.',
    },
    1723: {
        name: 'PPTP',
        risk: 'high',
        text: 'PPTP VPN is considered broken. Switch to WireGuard.',
    },
    1880: {
        name: 'Node-RED',
        risk: 'high',
        text: 'Node-RED editor. Allows running code, never expose it.',
    },
    1883: {
        name: 'MQTT',
        risk: 'high',
        text: 'Unencrypted MQTT. Often controls smart home devices.',
    },
    2375: {
        name: 'Docker API',
        risk: 'high',
        text: 'Unprotected Docker API = full control of the server.',
    },
    2376: {
        name: 'Docker API (TLS)',
        risk: 'high',
        text: 'Docker API. Should not face the internet.',
    },
    3306: {
        name: 'MySQL',
        risk: 'high',
        text: 'Database. Never expose directly.',
    },
    3389: {
        name: 'RDP',
        risk: 'high',
        text: 'Windows Remote Desktop. A top attack vector, use it via VPN only.',
    },
    5000: {
        name: 'NAS web UI',
        risk: 'medium',
        text: 'Often a NAS web UI (e.g. Synology).',
    },
    5001: {
        name: 'NAS web UI (HTTPS)',
        risk: 'medium',
        text: 'Often a NAS web UI (e.g. Synology).',
    },
    5432: {
        name: 'PostgreSQL',
        risk: 'high',
        text: 'Database. Never expose directly.',
    },
    5900: {
        name: 'VNC',
        risk: 'high',
        text: 'Screen sharing, often weakly protected. VPN only.',
    },
    6379: {
        name: 'Redis',
        risk: 'high',
        text: 'Redis often has no password. Never expose (ioBroker may use it!).',
    },
    7547: {
        name: 'TR-069',
        risk: 'low',
        text: 'Remote management by your ISP (TR-069).',
    },
    8080: {
        name: 'HTTP alt',
        risk: 'medium',
        text: 'Often device web UIs or test servers.',
    },
    8081: {
        name: 'ioBroker admin',
        risk: 'high',
        text: 'Default ioBroker admin port. Never expose.',
    },
    8082: {
        name: 'ioBroker web',
        risk: 'medium',
        text: 'Default ioBroker web server port.',
    },
    8087: {
        name: 'ioBroker simple-api',
        risk: 'high',
        text: 'ioBroker simple-api can switch devices.',
    },
    8089: {
        name: 'TR-069',
        risk: 'low',
        text: 'On FRITZ!Boxes usually the ISP remote management (TR-069). The box only accepts requests from the ISP there.',
    },
    8123: {
        name: 'Home Assistant',
        risk: 'medium',
        text: 'Home Assistant. Strong password and 2FA only.',
    },
    8443: { name: 'HTTPS alt', risk: 'low', text: 'Encrypted web UI.' },
    8883: {
        name: 'MQTT TLS',
        risk: 'medium',
        text: 'MQTT over TLS. Only with credentials.',
    },
    9000: {
        name: 'Portainer/misc',
        risk: 'high',
        text: 'Often Portainer (Docker management). Never expose.',
    },
    9200: {
        name: 'Elasticsearch',
        risk: 'high',
        text: 'Database without default password.',
    },
    11211: {
        name: 'Memcached',
        risk: 'high',
        text: 'Abused for attacks on others.',
    },
    27017: {
        name: 'MongoDB',
        risk: 'high',
        text: 'Database. Never expose directly.',
    },
    32400: { name: 'Plex', risk: 'low', text: 'Plex media server remote access.' },
};

const udp: Record<number, PortInfo> = {
    53: tcp[53],
    123: {
        name: 'NTP',
        risk: 'medium',
        text: 'Time server. Abused for attacks on others when open.',
    },
    161: {
        name: 'SNMP',
        risk: 'high',
        text: 'Device management, leaks a lot about your network.',
    },
    500: { name: 'IPsec', risk: 'low', text: 'IPsec VPN.' },
    1194: {
        name: 'OpenVPN',
        risk: 'low',
        text: 'OpenVPN. Fine with up-to-date software.',
    },
    1900: {
        name: 'SSDP/UPnP',
        risk: 'high',
        text: 'UPnP discovery. Never expose.',
    },
    4500: { name: 'IPsec NAT-T', risk: 'low', text: 'IPsec VPN.' },
    5060: {
        name: 'SIP',
        risk: 'medium',
        text: 'VoIP. Target of toll fraud.',
    },
    51820: {
        name: 'WireGuard',
        risk: 'low',
        text: 'WireGuard VPN. Only answers with a valid key and is invisible to scans.',
    },
};

export interface PortExplanation {
    name: string;
    risk: Risk;
    text: string;
}

export function explainPort(protocol: string, port: number): PortExplanation | undefined {
    const table = protocol.toUpperCase() === 'UDP' ? udp : tcp;
    const info = table[port];
    if (!info) {
        return undefined;
    }
    return { name: info.name, risk: info.risk, text: t(info.text) };
}

/** Services recognised by the name of a forwarding, for when a non-standard port is used. */
const BY_NAME: [RegExp, 'TCP' | 'UDP' | '*', PortInfo][] = [
    [/wire\s?guard|\bwg\d*\b/i, 'UDP', udp[51820]],
    [/openvpn|\bovpn\b/i, '*', udp[1194]],
    [/ipsec|l2tp/i, 'UDP', udp[500]],
    [/plex/i, 'TCP', tcp[32400]],
    [/\bssh\b|sftp/i, 'TCP', tcp[22]],
    [/\brdp\b|remote\s?desktop|remotedesktop/i, 'TCP', tcp[3389]],
    [/\bvnc\b/i, 'TCP', tcp[5900]],
    [/home\s?assistant/i, 'TCP', tcp[8123]],
    [/node-?red/i, 'TCP', tcp[1880]],
    [/mqtt/i, 'TCP', tcp[1883]],
    [/iobroker/i, 'TCP', tcp[8081]],
    [/\bftp\b/i, 'TCP', tcp[21]],
];

/**
 * Guesses the service from the description of a port forwarding (e.g. "WireGuard" on port 60000).
 */
export function explainByName(protocol: string, label: string | undefined): PortExplanation | undefined {
    if (!label) {
        return undefined;
    }
    const p = protocol.toUpperCase();
    const hit = BY_NAME.find(([re, proto]) => (proto === '*' || proto === p) && re.test(label));
    if (!hit) {
        return undefined;
    }
    const info = hit[2];
    return { name: info.name, risk: info.risk, text: t(info.text) };
}

/** Longer assessment for common services, shown in the expandable details. */
const ASSESSMENT: Record<string, string> = {
    WireGuard:
        'Low risk. WireGuard only answers packets with a valid key. A port scan sees nothing and there is no password to guess. Remaining risk: bugs in the WireGuard software of the target (keep it updated) and lost devices holding a key (e.g. an old phone) – delete peers you no longer use. A port other than 51820 does no harm but adds no security either.',
    OpenVPN:
        'Low risk when set up with certificates and tls-crypt/tls-auth. With password-only login, attackers can guess passwords. Keep the software updated.',
    IPsec: 'Low risk with a long random key. Short pre-shared keys can be cracked offline.',
    Plex: 'Low to medium risk. The server is reachable from the internet, login goes through your Plex account. Turn on two-factor login for the Plex account and keep the server updated.',
};

const GENERIC: Record<Risk, string> = {
    high: 'High risk. This service is attacked automatically all the time or is not meant for the internet. Better make it reachable via VPN only and delete the forwarding.',
    medium: 'Medium risk. Can be run safely, but only with a strong login and up-to-date software. Use a VPN if possible.',
    low: 'Low risk. The service is made for the internet. Keep the software updated.',
};

/**
 * Assessment text for the details of a port finding.
 */
export function assessPort(e: PortExplanation | undefined): string {
    if (!e) {
        return t(
            'Unknown service. Check on the target device which program uses this port. If you do not know: disable the forwarding and see what stops working.',
        );
    }
    return t(ASSESSMENT[e.name] ?? GENERIC[e.risk]);
}
