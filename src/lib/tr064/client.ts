import * as http from 'node:http';
import * as https from 'node:https';
import * as tls from 'node:tls';
import type { Duplex } from 'node:stream';
import { buildDigestHeader, parseDigestChallenge, type DigestChallenge } from './digest';
import { buildEnvelope, parseDeviceDescription, parseResponse, type DeviceDescription } from './soap';

const MAX_BODY = 8 * 1024 * 1024;
const DEFAULT_PORT = 49000;

export class CertificateMismatchError extends Error {
    public constructor(
        public readonly expected: string,
        public readonly actual: string,
    ) {
        super('The TLS certificate of the FRITZ!Box has changed');
        this.name = 'CertificateMismatchError';
    }
}

export class AuthError extends Error {
    public constructor(message = 'Login rejected by the FRITZ!Box (wrong user name or password, or missing rights)') {
        super(message);
        this.name = 'AuthError';
    }
}

export interface Tr064Options {
    host: string;
    username: string;
    password: string;
    /** Use the TLS port reported by the box (recommended). */
    useTls: boolean;
    /** SHA-256 fingerprint of the box certificate, as stored on first contact. */
    pinnedFingerprint?: string;
    timeoutMs?: number;
}

/**
 * An https agent that pins the self-signed FRITZ!Box certificate.
 * The socket is only handed to the request after the fingerprint was checked,
 * so no credentials are ever sent to a different peer.
 */
export class PinnedAgent extends https.Agent {
    public seenFingerprint = '';

    /** Without a stored pin the first certificate seen becomes the pin (trust on first use). */
    public constructor(public pinned: string | undefined) {
        super({ keepAlive: false });
    }

    public override createConnection(
        options: any,
        callback?: (err: Error | null, stream: Duplex) => void,
    ): Duplex | null | undefined {
        let done = false;
        const finish = (err: Error | null, s: Duplex): void => {
            if (!done) {
                done = true;
                callback?.(err, s);
            }
        };
        const socket = tls.connect({ ...options, rejectUnauthorized: false });
        // tls.connect sets the socket timeout from the request options, but nothing listens to it
        // before the socket is handed over. Without this a stalled handshake never ends.
        const onTimeout = (): void => {
            socket.destroy();
            finish(new Error('TLS handshake timeout'), socket);
        };
        socket.once('timeout', onTimeout);
        socket.once('secureConnect', () => {
            socket.off('timeout', onTimeout);
            const fp = socket.getPeerCertificate()?.fingerprint256 ?? '';
            this.seenFingerprint = fp;
            if (!fp) {
                socket.destroy();
                finish(new Error('The FRITZ!Box sent no certificate'), socket);
                return;
            }
            this.pinned ??= fp;
            if (fp !== this.pinned) {
                socket.destroy();
                finish(new CertificateMismatchError(this.pinned, fp), socket);
                return;
            }
            finish(null, socket);
        });
        socket.once('error', err => finish(err, socket));
        return undefined;
    }
}

interface RawResponse {
    status: number;
    headers: http.IncomingHttpHeaders;
    body: string;
}

function request(
    url: URL,
    opts: { method: string; headers?: Record<string, string>; body?: string; agent?: http.Agent; timeoutMs: number },
): Promise<RawResponse> {
    return new Promise((resolve, reject) => {
        const lib = url.protocol === 'https:' ? https : http;
        // the box answers chunked requests with 411, so always send a length
        const headers: Record<string, string> = { ...opts.headers };
        if (opts.body !== undefined) {
            headers['Content-Length'] = String(Buffer.byteLength(opts.body, 'utf8'));
        }
        const req = lib.request(
            url,
            { method: opts.method, headers, agent: opts.agent, timeout: opts.timeoutMs },
            res => {
                const chunks: Buffer[] = [];
                let size = 0;
                res.on('data', (c: Buffer) => {
                    size += c.length;
                    if (size > MAX_BODY) {
                        req.destroy(new Error('Response too large'));
                        return;
                    }
                    chunks.push(c);
                });
                res.on('end', () =>
                    resolve({
                        status: res.statusCode ?? 0,
                        headers: res.headers,
                        body: Buffer.concat(chunks).toString('utf8'),
                    }),
                );
                res.on('error', reject);
            },
        );
        req.on('timeout', () => req.destroy(new Error(`Timeout after ${opts.timeoutMs} ms`)));
        req.on('error', reject);
        // the timeout above only fires on idle sockets, a slowly dripping answer would never end
        const deadline = AbortSignal.timeout(3 * opts.timeoutMs);
        const onDeadline = (): void => {
            req.destroy(new Error(`No complete answer within ${3 * opts.timeoutMs} ms`));
        };
        deadline.addEventListener('abort', onDeadline, { once: true });
        req.on('close', () => deadline.removeEventListener('abort', onDeadline));
        if (opts.body) {
            req.write(opts.body);
        }
        req.end();
    });
}

export class Tr064Client {
    private description?: DeviceDescription;
    private base?: URL;
    private agent?: PinnedAgent;
    private challenge?: DigestChallenge;
    private nc = 0;
    private readonly timeoutMs: number;

    public constructor(private readonly opts: Tr064Options) {
        this.timeoutMs = opts.timeoutMs ?? 10_000;
    }

    /** Fingerprint of the certificate seen during the last TLS handshake. */
    public get certificateFingerprint(): string {
        return this.agent?.seenFingerprint ?? '';
    }

    /** The certificate this client trusts: the stored one, or the first one it saw. */
    public get pinnedFingerprint(): string {
        return this.agent?.pinned ?? '';
    }

    public get device(): DeviceDescription | undefined {
        return this.description;
    }

    /** Reads the public device description and, if wanted, switches to the TLS port. */
    public async connect(): Promise<DeviceDescription> {
        const plain = new URL(`http://${this.opts.host}:${DEFAULT_PORT}`);
        const res = await request(new URL('/tr64desc.xml', plain), { method: 'GET', timeoutMs: this.timeoutMs });
        if (res.status !== 200) {
            throw new Error(
                `TR-064 not reachable on ${this.opts.host} (HTTP ${res.status}). Is "Access for applications" enabled?`,
            );
        }
        this.description = parseDeviceDescription(res.body);
        this.base = plain;

        if (this.opts.useTls) {
            // GetSecurityPort is allowed without login
            const out = await this.rawCall('DeviceInfo:1', 'GetSecurityPort', {}, false);
            const port = Number(out.NewSecurityPort);
            if (!port) {
                throw new Error('The FRITZ!Box did not report a TLS port');
            }
            this.agent = new PinnedAgent(this.opts.pinnedFingerprint || undefined);
            this.base = new URL(`https://${this.opts.host}:${port}`);
        }
        return this.description;
    }

    public has(service: string): boolean {
        return !!this.findService(service);
    }

    private findService(service: string):
        | {
              serviceType: string;
              controlURL: string;
          }
        | undefined {
        if (!this.description) {
            return undefined;
        }
        const direct = this.description.services.get(service);
        if (direct) {
            return direct;
        }
        for (const [type, s] of this.description.services) {
            if (type.endsWith(`:service:${service}`)) {
                return s;
            }
        }
        return undefined;
    }

    /**
     * Calls a TR-064 action with digest authentication.
     */
    public call(
        service: string,
        action: string,
        args: Record<string, string | number> = {},
    ): Promise<Record<string, string>> {
        return this.rawCall(service, action, args, true);
    }

    private async rawCall(
        service: string,
        action: string,
        args: Record<string, string | number>,
        auth: boolean,
    ): Promise<Record<string, string>> {
        if (!this.base) {
            throw new Error('Not connected');
        }
        const svc = this.findService(service);
        if (!svc) {
            throw new Error(`Service ${service} is not available on this box`);
        }
        // the description comes over plain HTTP, so take only the path from it, never a host
        const path = new URL(svc.controlURL, 'http://box').pathname;
        const url = new URL(path, auth ? this.base : `http://${this.opts.host}:${DEFAULT_PORT}`);
        const body = buildEnvelope(svc.serviceType, action, args);
        const headers: Record<string, string> = {
            'Content-Type': 'text/xml; charset="utf-8"',
            SOAPACTION: `"${svc.serviceType}#${action}"`,
        };
        const agent = auth ? this.agent : undefined;

        let res = await this.send(url, body, headers, auth, agent);
        if (auth && res.status === 401) {
            const ch = parseDigestChallenge(res.headers['www-authenticate']);
            if (!ch) {
                throw new AuthError();
            }
            this.challenge = ch;
            this.nc = 0;
            res = await this.send(url, body, headers, auth, agent);
            if (res.status === 401) {
                this.challenge = undefined;
                throw new AuthError();
            }
        }
        if (res.status !== 200 && res.status !== 500) {
            throw new Error(`TR-064 ${action}: HTTP ${res.status}`);
        }
        return parseResponse(res.body, action);
    }

    private send(
        url: URL,
        body: string,
        headers: Record<string, string>,
        auth: boolean,
        agent?: http.Agent,
    ): Promise<RawResponse> {
        const h = { ...headers };
        if (auth && this.challenge) {
            h.Authorization = buildDigestHeader({
                challenge: this.challenge,
                method: 'POST',
                uri: url.pathname + url.search,
                username: this.opts.username,
                password: this.opts.password,
                nc: ++this.nc,
            });
        }
        return request(url, { method: 'POST', headers: h, body, agent, timeoutMs: this.timeoutMs });
    }

    /**
     * Downloads a file the box referenced in an action result (e.g. a log or call list URL with a session id).
     * Only paths on the box itself are allowed.
     */
    public async fetchFromBox(pathOrUrl: string): Promise<string> {
        if (!this.base) {
            throw new Error('Not connected');
        }
        const url = new URL(pathOrUrl, this.base);
        if (url.hostname !== this.base.hostname) {
            throw new Error('Refusing to fetch from a host other than the FRITZ!Box');
        }
        const agent = url.protocol === 'https:' ? this.agent : undefined;
        const res = await request(url, { method: 'GET', agent, timeoutMs: this.timeoutMs });
        if (res.status !== 200) {
            throw new Error(`Download from box failed: HTTP ${res.status}`);
        }
        return res.body;
    }

    public close(): void {
        this.agent?.destroy();
        this.challenge = undefined;
    }
}
