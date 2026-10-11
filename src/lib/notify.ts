import type { AdapterInstance } from '@iobroker/adapter-core';
import { SEVERITY_RANK, type Severity } from './findings';

export interface NotifyConfig {
    telegramEnabled: boolean;
    telegramInstance: string;
    telegramUser: string;
    emailEnabled: boolean;
    emailInstance: string;
    emailTo: string;
    minSeverity: Severity;
}

/** What happened to one message: targets that confirmed it and errors of the others. */
export interface SendResult {
    sent: number;
    errors: string[];
}

const ICON: Record<Severity, string> = { info: 'ℹ️', warning: '⚠️', critical: '🚨' };

/** Telegram allows 4096 characters, leave room for the title and the HTML entities. */
const MAX_TELEGRAM = 3500;
const MAX_MAIL = 20_000;

function escapeHtml(s: string): string {
    return s.replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c]!);
}

function cut(s: string, max: number): string {
    return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function instanceId(v: string): string {
    return v.replace(/^system\.adapter\./, '');
}

export class Notifier {
    public constructor(
        private readonly adapter: AdapterInstance,
        private readonly cfg: NotifyConfig,
    ) {}

    public get configured(): boolean {
        return (
            (this.cfg.telegramEnabled && !!this.cfg.telegramInstance) ||
            (this.cfg.emailEnabled && !!this.cfg.emailInstance)
        );
    }

    /**
     * Hands the message to the target adapter. Resolves when it answers, rejects on an error or when it does not answer in time.
     */
    private deliver(instance: string, msg: Record<string, unknown>, timeoutMs = 20_000): Promise<void> {
        return new Promise((resolve, reject) => {
            this.adapter.sendTo(
                instanceId(instance),
                'send',
                msg,
                (res: any) => {
                    // js-controller answers with an Error after the timeout
                    if (res instanceof Error) {
                        reject(res);
                    } else if (res && typeof res === 'object' && 'error' in res && res.error) {
                        reject(new Error(String(res.error)));
                    } else {
                        resolve();
                    }
                },
                { timeout: timeoutMs },
            );
        });
    }

    /**
     * Sends a message if its severity reaches the configured minimum (or `force` is set).
     * Texts may contain names from the box, so they are escaped, shortened and sent without link previews.
     */
    public async send(severity: Severity, title: string, text: string, force = false): Promise<SendResult> {
        const result: SendResult = { sent: 0, errors: [] };
        if (!force && SEVERITY_RANK[severity] < SEVERITY_RANK[this.cfg.minSeverity]) {
            return result;
        }
        const oneLineTitle = cut(title.replace(/\s+/g, ' ').trim(), 200);
        const jobs: Promise<unknown>[] = [];
        if (this.cfg.telegramEnabled && this.cfg.telegramInstance) {
            const msg: Record<string, unknown> = {
                text: `${ICON[severity]} <b>${escapeHtml(oneLineTitle)}</b>\n${escapeHtml(cut(text, MAX_TELEGRAM))}`,
                parse_mode: 'HTML',
                disable_web_page_preview: true,
            };
            if (this.cfg.telegramUser) {
                msg.user = this.cfg.telegramUser;
            }
            jobs.push(this.deliver(this.cfg.telegramInstance, msg));
        }
        if (this.cfg.emailEnabled && this.cfg.emailInstance) {
            const msg: Record<string, unknown> = {
                subject: `[fb-guard] ${oneLineTitle}`,
                text: cut(text, MAX_MAIL),
            };
            if (this.cfg.emailTo) {
                msg.to = this.cfg.emailTo;
            }
            jobs.push(this.deliver(this.cfg.emailInstance, msg));
        }
        for (const r of await Promise.allSettled(jobs)) {
            if (r.status === 'fulfilled') {
                result.sent++;
            } else {
                const err = String((r.reason as Error)?.message ?? r.reason);
                result.errors.push(err);
                this.adapter.log.warn(`Could not send notification: ${err}`);
            }
        }
        return result;
    }
}
