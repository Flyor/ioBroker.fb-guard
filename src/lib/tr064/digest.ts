import { createHash, randomBytes } from 'node:crypto';

export interface DigestChallenge {
    realm: string;
    nonce: string;
    qop?: string;
    opaque?: string;
    algorithm?: string;
    stale?: boolean;
}

function md5(s: string): string {
    return createHash('md5').update(s, 'utf8').digest('hex');
}

/**
 * Parses a `WWW-Authenticate: Digest ...` header. Returns undefined for other schemes.
 */
export function parseDigestChallenge(header: string | undefined): DigestChallenge | undefined {
    if (!header || !/^\s*Digest\s/i.test(header)) {
        return undefined;
    }
    const params: Record<string, string> = {};
    const re = /(\w+)=(?:"([^"]*)"|([^\s,]+))/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(header)) !== null) {
        params[m[1].toLowerCase()] = m[2] ?? m[3];
    }
    if (!params.realm || !params.nonce) {
        return undefined;
    }
    return {
        realm: params.realm,
        nonce: params.nonce,
        qop: params.qop,
        opaque: params.opaque,
        algorithm: params.algorithm,
        stale: params.stale?.toLowerCase() === 'true',
    };
}

/**
 * Builds the Authorization header for HTTP digest auth (RFC 2617, MD5, qop=auth).
 * The password itself never leaves this function.
 */
export function buildDigestHeader(opts: {
    challenge: DigestChallenge;
    method: string;
    uri: string;
    username: string;
    password: string;
    nc: number;
    cnonce?: string;
}): string {
    const { challenge, method, uri, username, password, nc } = opts;
    const cnonce = opts.cnonce ?? randomBytes(8).toString('hex');
    const ncHex = nc.toString(16).padStart(8, '0');
    const ha1 = md5(`${username}:${challenge.realm}:${password}`);
    const ha2 = md5(`${method}:${uri}`);
    const useQop = challenge.qop?.split(',').some(q => q.trim() === 'auth');
    const response = useQop
        ? md5(`${ha1}:${challenge.nonce}:${ncHex}:${cnonce}:auth:${ha2}`)
        : md5(`${ha1}:${challenge.nonce}:${ha2}`);

    const parts = [
        `username="${username.replace(/"/g, '\\"')}"`,
        `realm="${challenge.realm}"`,
        `nonce="${challenge.nonce}"`,
        `uri="${uri}"`,
        `response="${response}"`,
    ];
    if (challenge.algorithm) {
        parts.push(`algorithm=${challenge.algorithm}`);
    }
    if (challenge.opaque) {
        parts.push(`opaque="${challenge.opaque}"`);
    }
    if (useQop) {
        parts.push('qop=auth', `nc=${ncHex}`, `cnonce="${cnonce}"`);
    }
    return `Digest ${parts.join(', ')}`;
}
