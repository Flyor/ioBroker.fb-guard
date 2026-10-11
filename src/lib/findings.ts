import { createHash } from 'node:crypto';

export type Severity = 'info' | 'warning' | 'critical';
export type Category = 'ports' | 'firmware' | 'settings' | 'connection';

export interface Finding {
    /** Stable id. For ports it contains port, protocol and target, so any change creates a new finding. */
    id: string;
    category: Category;
    severity: Severity;
    title: string;
    detail: string;
    advice?: string;
    /** Longer explanation for the expandable details. Not part of the hash. */
    more?: string;
    /** Can be confirmed as "intended" by the user. */
    ackable?: boolean;
}

export interface StoredFinding extends Finding {
    hash: string;
    firstSeen: number;
    lastSeen: number;
}

export interface Diff {
    added: StoredFinding[];
    changed: StoredFinding[];
    resolved: StoredFinding[];
}

export const SEVERITY_RANK: Record<Severity, number> = { info: 0, warning: 1, critical: 2 };

function hashOf(f: Finding): string {
    return createHash('sha1').update(`${f.severity}|${f.title}|${f.detail}`).digest('hex').slice(0, 12);
}

export class FindingStore {
    private readonly items = new Map<string, StoredFinding>();
    private readonly acked = new Set<string>();

    public load(
        data:
            | {
                  items?: StoredFinding[];
                  acked?: string[];
              }
            | undefined,
    ): void {
        this.items.clear();
        this.acked.clear();
        // the state can be edited by hand, so skip anything that does not look like a finding
        const items = Array.isArray(data?.items) ? data.items : [];
        for (const i of items) {
            if (
                i &&
                typeof i.id === 'string' &&
                typeof i.title === 'string' &&
                typeof i.detail === 'string' &&
                Object.hasOwn(SEVERITY_RANK, i.severity)
            ) {
                this.items.set(i.id, i);
            }
        }
        for (const a of Array.isArray(data?.acked) ? data.acked : []) {
            if (typeof a === 'string') {
                this.acked.add(a);
            }
        }
    }

    public dump(): {
        items: StoredFinding[];
        acked: string[];
    } {
        return { items: [...this.items.values()], acked: [...this.acked] };
    }

    /**
     * Replaces all findings of a category and reports what changed.
     */
    public update(category: Category, current: Finding[], now = Date.now()): Diff {
        const diff: Diff = { added: [], changed: [], resolved: [] };
        const seen = new Set<string>();
        for (const f of current) {
            seen.add(f.id);
            const hash = hashOf(f);
            const prev = this.items.get(f.id);
            const stored: StoredFinding = { ...f, hash, firstSeen: prev?.firstSeen ?? now, lastSeen: now };
            this.items.set(f.id, stored);
            if (!prev) {
                diff.added.push(stored);
            } else if (prev.hash !== hash) {
                diff.changed.push(stored);
            }
        }
        for (const [id, f] of this.items) {
            if (f.category === category && !seen.has(id)) {
                this.items.delete(id);
                diff.resolved.push(f);
            }
        }
        return diff;
    }

    public acknowledge(id: string): boolean {
        const f = this.items.get(id);
        if (!f?.ackable) {
            return false;
        }
        this.acked.add(id);
        return true;
    }

    public unacknowledge(id: string): void {
        this.acked.delete(id);
    }

    public isAcked(id: string): boolean {
        return this.acked.has(id);
    }

    /** Drops acknowledgements for findings that no longer exist. */
    public pruneAcks(): void {
        for (const id of this.acked) {
            if (!this.items.has(id)) {
                this.acked.delete(id);
            }
        }
    }

    public all(): StoredFinding[] {
        return [...this.items.values()].sort(
            (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.id.localeCompare(b.id),
        );
    }

    public open(): StoredFinding[] {
        return this.all().filter(f => !this.acked.has(f.id));
    }

    /** 100 = nothing open. Hints (info) do not count, critical findings weigh most. */
    public score(): number {
        let s = 100;
        for (const f of this.open()) {
            s -= f.severity === 'critical' ? 25 : f.severity === 'warning' ? 10 : 0;
        }
        return Math.max(0, s);
    }
}
