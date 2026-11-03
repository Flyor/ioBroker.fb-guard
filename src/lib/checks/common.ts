import type { Tr064Client } from '../tr064/client';
import { Tr064Fault } from '../tr064/soap';

export interface CheckContext {
    client: Tr064Client;
    log: ioBroker.Logger;
}

/**
 * Calls an action and returns undefined if the service is missing or the box refuses the action
 * (SOAP fault, e.g. missing rights). Everything else is re-thrown: if the box does not answer,
 * the run must stop. Otherwise missing answers would look like resolved findings.
 */
export async function tryCall(
    ctx: CheckContext,
    service: string,
    action: string,
    args: Record<string, string | number> = {},
): Promise<Record<string, string> | undefined> {
    if (!ctx.client.has(service)) {
        return undefined;
    }
    try {
        return await ctx.client.call(service, action, args);
    } catch (e) {
        if (!(e instanceof Tr064Fault)) {
            throw e;
        }
        ctx.log.debug(`${service} ${action}: ${e.message}`);
        return undefined;
    }
}

export const isOn = (v: string | undefined): boolean => v === '1' || v?.toLowerCase() === 'true';
