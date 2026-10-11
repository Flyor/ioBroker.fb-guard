export type Risk = 'high' | 'medium' | 'low';
export type Lang = 'de' | 'en';

interface PortInfo {
    name: string;
    risk: Risk;
    de: string;
    en: string;
}

const tcp: Record<number, PortInfo> = {
    21: {
        name: 'FTP',
        risk: 'high',
        de: 'FTP überträgt Passwörter unverschlüsselt.',
        en: 'FTP sends passwords in clear text.',
    },
    22: {
        name: 'SSH',
        risk: 'medium',
        de: 'SSH-Zugang. Wird ständig von Bots mit Passwortlisten angegriffen, nur mit Schlüssel-Login betreiben.',
        en: 'SSH access. Constantly hit by password-guessing bots, use key-based login only.',
    },
    23: {
        name: 'Telnet',
        risk: 'high',
        de: 'Telnet ist unverschlüsselt und gehört nie ins Internet.',
        en: 'Telnet is unencrypted and should never face the internet.',
    },
    25: {
        name: 'SMTP',
        risk: 'medium',
        de: 'Mailserver. Offen nur sinnvoll, wenn du wirklich einen betreibst.',
        en: 'Mail server. Only makes sense if you really run one.',
    },
    53: {
        name: 'DNS',
        risk: 'high',
        de: 'Ein offener DNS-Server wird gern für Angriffe auf Dritte missbraucht.',
        en: 'Open DNS resolvers get abused for attacks on others.',
    },
    80: {
        name: 'HTTP',
        risk: 'medium',
        de: 'Unverschlüsselte Webseite. Besser nur HTTPS freigeben.',
        en: 'Unencrypted web server. Prefer exposing HTTPS only.',
    },
    111: {
        name: 'RPC',
        risk: 'high',
        de: 'RPC-Dienst (oft NAS/NFS). Gehört nicht ins Internet.',
        en: 'RPC service (often NAS/NFS). Should not face the internet.',
    },
    139: {
        name: 'NetBIOS',
        risk: 'high',
        de: 'Windows-Dateifreigabe. Gehört nie ins Internet.',
        en: 'Windows file sharing. Never expose to the internet.',
    },
    443: {
        name: 'HTTPS',
        risk: 'low',
        de: 'Verschlüsselte Webseite oder Reverse-Proxy.',
        en: 'Encrypted web server or reverse proxy.',
    },
    445: {
        name: 'SMB',
        risk: 'high',
        de: 'Windows-/NAS-Dateifreigabe. Häufiges Ziel von Ransomware, nie freigeben.',
        en: 'Windows/NAS file sharing. Common ransomware target, never expose.',
    },
    1723: {
        name: 'PPTP',
        risk: 'high',
        de: 'PPTP-VPN gilt als gebrochen. Auf WireGuard umsteigen.',
        en: 'PPTP VPN is considered broken. Switch to WireGuard.',
    },
    1880: {
        name: 'Node-RED',
        risk: 'high',
        de: 'Node-RED-Editor. Erlaubt das Ausführen von Code, nie offen freigeben.',
        en: 'Node-RED editor. Allows running code, never expose it.',
    },
    1883: {
        name: 'MQTT',
        risk: 'high',
        de: 'Unverschlüsseltes MQTT. Steuert oft Smarthome-Geräte.',
        en: 'Unencrypted MQTT. Often controls smart home devices.',
    },
    2375: {
        name: 'Docker API',
        risk: 'high',
        de: 'Docker-API ohne Schutz = volle Kontrolle über den Server.',
        en: 'Unprotected Docker API = full control of the server.',
    },
    2376: {
        name: 'Docker API (TLS)',
        risk: 'high',
        de: 'Docker-API. Gehört nicht ins Internet.',
        en: 'Docker API. Should not face the internet.',
    },
    3306: {
        name: 'MySQL',
        risk: 'high',
        de: 'Datenbank. Gehört nie direkt ins Internet.',
        en: 'Database. Never expose directly.',
    },
    3389: {
        name: 'RDP',
        risk: 'high',
        de: 'Windows-Remotedesktop. Eines der häufigsten Einfallstore, nur über VPN nutzen.',
        en: 'Windows Remote Desktop. A top attack vector, use it via VPN only.',
    },
    5000: {
        name: 'NAS web UI',
        risk: 'medium',
        de: 'Oft die Weboberfläche eines NAS (z. B. Synology).',
        en: 'Often a NAS web UI (e.g. Synology).',
    },
    5001: {
        name: 'NAS web UI (HTTPS)',
        risk: 'medium',
        de: 'Oft die Weboberfläche eines NAS (z. B. Synology).',
        en: 'Often a NAS web UI (e.g. Synology).',
    },
    5432: {
        name: 'PostgreSQL',
        risk: 'high',
        de: 'Datenbank. Gehört nie direkt ins Internet.',
        en: 'Database. Never expose directly.',
    },
    5900: {
        name: 'VNC',
        risk: 'high',
        de: 'Bildschirmfreigabe, oft schwach geschützt. Nur über VPN.',
        en: 'Screen sharing, often weakly protected. VPN only.',
    },
    6379: {
        name: 'Redis',
        risk: 'high',
        de: 'Redis hat oft kein Passwort. Nie freigeben (ioBroker nutzt es teilweise!).',
        en: 'Redis often has no password. Never expose (ioBroker may use it!).',
    },
    7547: {
        name: 'TR-069',
        risk: 'low',
        de: 'Fernwartung durch deinen Internetanbieter (TR-069).',
        en: 'Remote management by your ISP (TR-069).',
    },
    8080: {
        name: 'HTTP alt',
        risk: 'medium',
        de: 'Häufig Weboberflächen von Geräten oder Testservern.',
        en: 'Often device web UIs or test servers.',
    },
    8081: {
        name: 'ioBroker admin',
        risk: 'high',
        de: 'Standardport der ioBroker-Admin-Oberfläche. Nie offen freigeben.',
        en: 'Default ioBroker admin port. Never expose.',
    },
    8082: {
        name: 'ioBroker web',
        risk: 'medium',
        de: 'Standardport des ioBroker-Webservers.',
        en: 'Default ioBroker web server port.',
    },
    8087: {
        name: 'ioBroker simple-api',
        risk: 'high',
        de: 'ioBroker simple-api erlaubt das Schalten von Geräten.',
        en: 'ioBroker simple-api can switch devices.',
    },
    8089: {
        name: 'TR-069',
        risk: 'low',
        de: 'Bei FRITZ!Boxen meist die TR-069-Fernwartung des Internetanbieters. Die Box nimmt dort nur Anfragen des Anbieters an.',
        en: 'On FRITZ!Boxes usually the ISP remote management (TR-069). The box only accepts requests from the ISP there.',
    },
    8123: {
        name: 'Home Assistant',
        risk: 'medium',
        de: 'Home Assistant. Nur mit starkem Passwort und 2FA.',
        en: 'Home Assistant. Strong password and 2FA only.',
    },
    8443: { name: 'HTTPS alt', risk: 'low', de: 'Verschlüsselte Weboberfläche.', en: 'Encrypted web UI.' },
    8883: {
        name: 'MQTT TLS',
        risk: 'medium',
        de: 'MQTT mit Verschlüsselung. Nur mit Zugangsdaten.',
        en: 'MQTT over TLS. Only with credentials.',
    },
    9000: {
        name: 'Portainer/misc',
        risk: 'high',
        de: 'Oft Portainer (Docker-Verwaltung). Nie offen freigeben.',
        en: 'Often Portainer (Docker management). Never expose.',
    },
    9200: {
        name: 'Elasticsearch',
        risk: 'high',
        de: 'Datenbank ohne Standard-Passwort.',
        en: 'Database without default password.',
    },
    11211: {
        name: 'Memcached',
        risk: 'high',
        de: 'Wird für Angriffe auf Dritte missbraucht.',
        en: 'Abused for attacks on others.',
    },
    27017: {
        name: 'MongoDB',
        risk: 'high',
        de: 'Datenbank. Gehört nie direkt ins Internet.',
        en: 'Database. Never expose directly.',
    },
    32400: { name: 'Plex', risk: 'low', de: 'Plex-Mediaserver-Fernzugriff.', en: 'Plex media server remote access.' },
};

const udp: Record<number, PortInfo> = {
    53: tcp[53],
    123: {
        name: 'NTP',
        risk: 'medium',
        de: 'Zeitserver. Offen wird er für Angriffe auf Dritte missbraucht.',
        en: 'Time server. Abused for attacks on others when open.',
    },
    161: {
        name: 'SNMP',
        risk: 'high',
        de: 'Geräteverwaltung, verrät viel über dein Netz.',
        en: 'Device management, leaks a lot about your network.',
    },
    500: { name: 'IPsec', risk: 'low', de: 'IPsec-VPN.', en: 'IPsec VPN.' },
    1194: {
        name: 'OpenVPN',
        risk: 'low',
        de: 'OpenVPN. Bei aktueller Software unbedenklich.',
        en: 'OpenVPN. Fine with up-to-date software.',
    },
    1900: {
        name: 'SSDP/UPnP',
        risk: 'high',
        de: 'UPnP-Erkennung. Gehört nie ins Internet.',
        en: 'UPnP discovery. Never expose.',
    },
    4500: { name: 'IPsec NAT-T', risk: 'low', de: 'IPsec-VPN.', en: 'IPsec VPN.' },
    5060: {
        name: 'SIP',
        risk: 'medium',
        de: 'Internettelefonie. Ziel von Gebührenbetrug.',
        en: 'VoIP. Target of toll fraud.',
    },
    51820: {
        name: 'WireGuard',
        risk: 'low',
        de: 'WireGuard-VPN. Antwortet nur mit gültigem Schlüssel und ist bei Scans unsichtbar.',
        en: 'WireGuard VPN. Only answers with a valid key and is invisible to scans.',
    },
};

export interface PortExplanation {
    name: string;
    risk: Risk;
    text: string;
}

export function explainPort(protocol: string, port: number, lang: Lang): PortExplanation | undefined {
    const table = protocol.toUpperCase() === 'UDP' ? udp : tcp;
    const info = table[port];
    if (!info) {
        return undefined;
    }
    return { name: info.name, risk: info.risk, text: lang === 'de' ? info.de : info.en };
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
export function explainByName(protocol: string, label: string | undefined, lang: Lang): PortExplanation | undefined {
    if (!label) {
        return undefined;
    }
    const p = protocol.toUpperCase();
    const hit = BY_NAME.find(([re, proto]) => (proto === '*' || proto === p) && re.test(label));
    if (!hit) {
        return undefined;
    }
    const info = hit[2];
    return { name: info.name, risk: info.risk, text: lang === 'de' ? info.de : info.en };
}

/** Longer assessment for common services, shown in the expandable details. */
const ASSESSMENT: Record<string, { de: string; en: string }> = {
    WireGuard: {
        de: 'Geringes Risiko. WireGuard antwortet nur auf Pakete mit gültigem Schlüssel. Ein Portscan sieht nichts, es gibt kein Passwort zum Raten. Restrisiko: Lücken in der WireGuard-Software des Zielgeräts (aktuell halten) und verlorene Geräte mit Schlüssel (z. B. altes Handy) – nicht mehr genutzte Peers löschen. Ein anderer Port als 51820 schadet nicht, bringt aber auch keine Sicherheit.',
        en: 'Low risk. WireGuard only answers packets with a valid key. A port scan sees nothing and there is no password to guess. Remaining risk: bugs in the WireGuard software of the target (keep it updated) and lost devices holding a key (e.g. an old phone) – delete peers you no longer use. A port other than 51820 does no harm but adds no security either.',
    },
    OpenVPN: {
        de: 'Geringes Risiko, wenn mit Zertifikaten und tls-crypt/tls-auth eingerichtet. Mit reiner Passwort-Anmeldung kann ein Angreifer Passwörter raten. Software aktuell halten.',
        en: 'Low risk when set up with certificates and tls-crypt/tls-auth. With password-only login, attackers can guess passwords. Keep the software updated.',
    },
    IPsec: {
        de: 'Geringes Risiko bei langem, zufälligem Schlüssel. Kurze Pre-Shared-Keys lassen sich offline knacken.',
        en: 'Low risk with a long random key. Short pre-shared keys can be cracked offline.',
    },
    Plex: {
        de: 'Geringes bis mittleres Risiko. Der Server ist aus dem Internet erreichbar, die Anmeldung läuft über dein Plex-Konto. Zwei-Faktor-Anmeldung im Plex-Konto einschalten und den Server aktuell halten.',
        en: 'Low to medium risk. The server is reachable from the internet, login goes through your Plex account. Turn on two-factor login for the Plex account and keep the server updated.',
    },
};

const GENERIC: Record<Risk, { de: string; en: string }> = {
    high: {
        de: 'Hohes Risiko. Dieser Dienst wird ständig automatisiert angegriffen oder ist nicht für das Internet gedacht. Besser nur über VPN erreichbar machen und die Freigabe löschen.',
        en: 'High risk. This service is attacked automatically all the time or is not meant for the internet. Better make it reachable via VPN only and delete the forwarding.',
    },
    medium: {
        de: 'Mittleres Risiko. Sicher betreibbar, aber nur mit starkem Login und aktueller Software. Wenn möglich nur über VPN.',
        en: 'Medium risk. Can be run safely, but only with a strong login and up-to-date software. Use a VPN if possible.',
    },
    low: {
        de: 'Geringes Risiko. Der Dienst ist für das Internet gemacht. Software aktuell halten.',
        en: 'Low risk. The service is made for the internet. Keep the software updated.',
    },
};

/**
 * Assessment text for the details of a port finding.
 */
export function assessPort(e: PortExplanation | undefined, lang: Lang): string {
    if (!e) {
        return lang === 'de'
            ? 'Unbekannter Dienst. Prüfe am Zielgerät, welches Programm diesen Port nutzt. Weißt du es nicht: Freigabe deaktivieren und schauen, was danach nicht mehr geht.'
            : 'Unknown service. Check on the target device which program uses this port. If you do not know: disable the forwarding and see what stops working.';
    }
    const a = ASSESSMENT[e.name] ?? GENERIC[e.risk];
    return lang === 'de' ? a.de : a.en;
}
