import { XMLParser } from 'fast-xml-parser';

const parser = new XMLParser({
    ignoreAttributes: true,
    removeNSPrefix: true,
    parseTagValue: false,
    trimValues: true,
});

export class Tr064Fault extends Error {
    public constructor(
        public readonly code: number,
        public readonly description: string,
        public readonly action: string,
    ) {
        super(`TR-064 ${action} failed: ${code} ${description}`);
        this.name = 'Tr064Fault';
    }
}

export function escapeXml(s: string): string {
    return s.replace(/[<>&'"]/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', "'": '&apos;', '"': '&quot;' })[c]!);
}

export function buildEnvelope(serviceType: string, action: string, args: Record<string, string | number> = {}): string {
    const body = Object.entries(args)
        .map(([k, v]) => `<${k}>${escapeXml(String(v))}</${k}>`)
        .join('');
    return (
        '<?xml version="1.0" encoding="utf-8"?>' +
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ' +
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">' +
        `<s:Body><u:${action} xmlns:u="${escapeXml(serviceType)}">${body}</u:${action}></s:Body></s:Envelope>`
    );
}

/**
 * Extracts the out-arguments of a SOAP response, or throws a Tr064Fault.
 */
export function parseResponse(xml: string, action: string): Record<string, string> {
    const doc = parser.parse(xml);
    const body = doc?.Envelope?.Body;
    if (!body) {
        throw new Error(`TR-064 ${action}: invalid SOAP response`);
    }
    if (body.Fault) {
        const err = body.Fault?.detail?.UPnPError ?? {};
        throw new Tr064Fault(Number(err.errorCode ?? 0), String(err.errorDescription ?? 'unknown'), action);
    }
    const res = body[`${action}Response`];
    const out: Record<string, string> = {};
    if (res && typeof res === 'object') {
        for (const [k, v] of Object.entries(res)) {
            if (v == null) {
                out[k] = '';
            } else if (typeof v === 'object') {
                const text = (v as Record<string, unknown>)['#text'];
                out[k] = typeof text === 'string' || typeof text === 'number' ? String(text) : '';
            } else {
                out[k] = typeof v === 'string' ? v : JSON.stringify(v);
            }
        }
    }
    return out;
}

export interface ServiceInfo {
    serviceType: string;
    controlURL: string;
    SCPDURL: string;
}

export interface DeviceDescription {
    modelName: string;
    friendlyName: string;
    firmware: string;
    services: Map<string, ServiceInfo>;
}

function asArray<T>(v: T | T[] | undefined): T[] {
    return v === undefined ? [] : Array.isArray(v) ? v : [v];
}

/**
 * Parses tr64desc.xml into a serviceType -> service map.
 */
export function parseDeviceDescription(xml: string): DeviceDescription {
    const doc = parser.parse(xml);
    const root = doc?.root;
    if (!root?.device) {
        throw new Error('Not a TR-064 device description');
    }
    const services = new Map<string, ServiceInfo>();
    const walk = (dev: any): void => {
        for (const s of asArray<any>(dev?.serviceList?.service)) {
            if (s?.serviceType && s?.controlURL) {
                services.set(String(s.serviceType), {
                    serviceType: String(s.serviceType),
                    controlURL: String(s.controlURL),
                    SCPDURL: String(s.SCPDURL ?? ''),
                });
            }
        }
        for (const d of asArray<any>(dev?.deviceList?.device)) {
            walk(d);
        }
    };
    walk(root.device);
    return {
        modelName: String(root.device.modelName ?? ''),
        friendlyName: String(root.device.friendlyName ?? ''),
        firmware: String(root.systemVersion?.Display ?? ''),
        services,
    };
}

/**
 * Parses small XML documents (e.g. user lists returned as strings).
 */
export function parseXml(xml: string): any {
    return parser.parse(xml);
}
