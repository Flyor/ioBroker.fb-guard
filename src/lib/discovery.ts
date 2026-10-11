import * as dgram from 'node:dgram';
import * as http from 'node:http';
import { parseDeviceDescription } from './tr064/soap';

export interface FoundBox {
    host: string;
    model: string;
    firmware: string;
}

function getDesc(host: string, timeoutMs: number): Promise<FoundBox | undefined> {
    return new Promise(resolve => {
        const req = http.get(
            {
                host,
                port: 49000,
                path: '/tr64desc.xml',
                timeout: timeoutMs,
                signal: AbortSignal.timeout(3 * timeoutMs),
            },
            res => {
                if (res.statusCode !== 200) {
                    res.resume();
                    resolve(undefined);
                    return;
                }
                let body = '';
                res.setEncoding('utf8');
                res.on('data', (c: string) => {
                    body += c;
                    if (body.length > 512 * 1024) {
                        req.destroy();
                    }
                });
                // a destroyed or aborted answer never ends, settle anyway (no-op after 'end')
                res.on('close', () => resolve(undefined));
                res.on('end', () => {
                    try {
                        const d = parseDeviceDescription(body);
                        resolve({ host, model: d.modelName, firmware: d.firmware });
                    } catch {
                        resolve(undefined);
                    }
                });
            },
        );
        req.on('timeout', () => req.destroy());
        req.on('error', () => resolve(undefined));
        req.on('close', () => resolve(undefined));
    });
}

/**
 * Asks the local network via SSDP for TR-064 devices.
 */
function ssdp(timers: Timers, timeoutMs: number): Promise<string[]> {
    return new Promise(resolve => {
        const hosts = new Set<string>();
        const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
        const msg = Buffer.from(
            'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\n' +
                'ST: urn:dslforum-org:device:InternetGatewayDevice:1\r\n\r\n',
        );
        sock.on('message', (_m, rinfo) => hosts.add(rinfo.address));
        sock.on('error', () => {
            sock.close();
            resolve([...hosts]);
        });
        const done = (): void => {
            try {
                sock.close();
            } catch {
                // already closed
            }
            resolve([...hosts]);
        };
        sock.bind(() => {
            sock.send(msg, 1900, '239.255.255.250');
            // undefined when the adapter is being stopped
            if (!timers.setTimeout(done, timeoutMs)) {
                done();
            }
        });
    });
}

/** The adapter's timers, so nothing outlives an unload. */
export type Timers = Pick<ioBroker.Adapter, 'setTimeout'>;

export async function discoverBoxes(timers: Timers): Promise<FoundBox[]> {
    const candidates = new Set([
        'fritz.box',
        '192.168.178.1',
        '192.168.0.1',
        '192.168.188.1',
        '192.168.2.1',
        '192.168.1.1',
    ]);
    for (const h of await ssdp(timers, 2500)) {
        candidates.add(h);
    }
    const results = await Promise.all([...candidates].map(h => getDesc(h, 2500)));
    const seen = new Set<string>();
    return results.filter((r): r is FoundBox => {
        if (!r || !/fritz/i.test(r.model)) {
            return false;
        }
        const key = `${r.model}|${r.firmware}`;
        if (seen.has(key) && r.host === 'fritz.box') {
            return false;
        }
        seen.add(key);
        return true;
    });
}
