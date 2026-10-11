/*
 * fb-guard - security monitoring for FRITZ!Box routers via TR-064.
 */

import { networkInterfaces } from 'node:os';
import * as utils from '@iobroker/adapter-core';
import { checkExposure } from './lib/checks/exposure';
import { describeHosts, readHosts } from './lib/checks/devices';
import { evaluateEvents, readDeviceLog } from './lib/checks/events';
import { checkFirmware } from './lib/checks/firmware';
import { checkSettings } from './lib/checks/settings';
import { L, type CheckContext } from './lib/checks/common';
import { runDiagnostics } from './lib/diagnostics';
import { discoverBoxes } from './lib/discovery';
import { FindingStore, SEVERITY_RANK, type Category, type Diff, type Finding, type Severity } from './lib/findings';
import { learnHomeIpv6, parseIpList } from './lib/ip';
import type { Lang } from './lib/knowledge/ports';
import { freshEvents, type SeenEvents } from './lib/logparser';
import { Notifier, type SendResult } from './lib/notify';
import { ICON as SEVERITY_ICON, esc, findingsHtml, summaryMessage } from './lib/render';
import { AuthError, CertificateMismatchError, Tr064Client } from './lib/tr064/client';

/** Failed runs in a row before the outage is reported. */
const OUTAGE_RUNS = 3;
/** Format of events.seen. Older formats are replaced by the next read, without alerts. */
const SEEN_FORMAT = 2;
const MIN = 60_000;

/** One row of the confirmation table in the settings. */
type ConfirmationRow = ioBroker.AdapterConfig['confirmations'][number];

/** Allowed check intervals in minutes [min, max, default]. Shorter ones load the box, longer ones miss too much. */
const INTERVALS = {
    intervalEvents: [1, 60, 5],
    intervalPorts: [15, 1440, 60],
    intervalSettings: [15, 1440, 60],
    intervalFirmware: [60, 10080, 720],
} as const;

/** Errors that mean the box did not answer (as opposed to bugs or unexpected answers). */
function isNetworkError(err: Error): boolean {
    const code = (err as NodeJS.ErrnoException).code ?? '';
    return (
        /^(ECONNREFUSED|ECONNRESET|EHOSTUNREACH|ENETUNREACH|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|EPIPE|ECONNABORTED)$/.test(
            code,
        ) || /timeout|No complete answer|not reachable|socket hang up|did not report a TLS port/i.test(err.message)
    );
}

function clampInterval(key: keyof typeof INTERVALS, value: unknown, log: ioBroker.Logger): number {
    const [min, max, def] = INTERVALS[key];
    const v = Number(value);
    if (!Number.isFinite(v) || v <= 0) {
        return def;
    }
    const res = Math.min(max, Math.max(min, Math.round(v)));
    if (res !== v) {
        log.warn(`${key}: ${v} min is outside ${min}-${max}, using ${res} min`);
    }
    return res;
}

class FbGuard extends utils.Adapter {
    private client?: Tr064Client;
    /** Sends nothing until onReady has read the config. */
    private notifier = new Notifier(this, {
        telegramEnabled: false,
        telegramInstance: '',
        telegramUser: '',
        emailEnabled: false,
        emailInstance: '',
        emailTo: '',
        minSeverity: 'critical',
    });
    /** Jobs that wait in the queue, so a tick or button press does not add the same job twice. */
    private readonly pending = new Set<string>();
    private readonly store = new FindingStore();
    private initialized = new Set<Category>();
    /** Categories whose stored texts are still in the previous system language. */
    private relabel = new Set<Category>();
    private lang: Lang = 'en';
    private queue: Promise<void> = Promise.resolve();
    private timers: ioBroker.Interval[] = [];
    /** Set after a login or certificate problem; no further logins until the config changes. */
    private blocked = false;
    private seenEvents: SeenEvents = {};
    private eventsInitialized = false;
    /** Older versions stored a different format: take the next read as baseline, without alerts. */
    private eventsSilent = false;
    private summaryTimer?: ioBroker.Timeout;
    private devicesCache?: { at: number; html: string };
    private lastUptime?: number;
    /** Runs in a row that failed because the box did not answer. */
    private failedRuns = 0;
    private outageNotified = false;
    private knownUsers?: string[];
    /** Set on unload, queued jobs are skipped from then on. */
    private stopping = false;

    public constructor(options: Partial<utils.AdapterOptions> = {}) {
        super({ ...options, name: 'fb-guard' });
        this.on('ready', this.onReady.bind(this));
        this.on('stateChange', this.onStateChange.bind(this));
        this.on('message', this.onMessage.bind(this));
        this.on('unload', this.onUnload.bind(this));
    }

    private async onReady(): Promise<void> {
        await this.setState('info.connection', false, true);
        const sys = await this.getForeignObjectAsync('system.config');
        this.lang = sys?.common?.language === 'de' ? 'de' : 'en';

        this.notifier = new Notifier(this, {
            telegramEnabled: !!this.config.telegramEnabled,
            telegramInstance: this.config.telegramInstance ?? '',
            telegramUser: this.config.telegramUser ?? '',
            emailEnabled: !!this.config.emailEnabled,
            emailInstance: this.config.emailInstance ?? '',
            emailTo: this.config.emailTo ?? '',
            minSeverity: this.config.minSeverity || 'warning',
        });

        await this.loadPersisted();
        await this.applyConfirmations();
        this.subscribeStates('findings.acknowledge');
        this.subscribeStates('findings.unacknowledge');
        this.subscribeStates('actions.runNow');

        if (!this.config.host || !this.config.username || !this.config.password) {
            this.log.warn(
                'Setup not finished: please enter the FRITZ!Box address, user and password in the adapter settings.',
            );
            return;
        }

        await this.runAll();
        const every = (key: keyof typeof INTERVALS, fn: () => Promise<void>): void => {
            const iv = this.setInterval(
                () => this.enqueue(fn, key),
                clampInterval(key, this.config[key], this.log) * MIN,
            );
            if (iv) {
                this.timers.push(iv);
            }
        };
        every('intervalEvents', () => this.runEvents());
        every('intervalPorts', () => this.runPorts());
        every('intervalSettings', () => this.runSettings());
        every('intervalFirmware', () => this.runFirmware());
        this.scheduleSummary();
    }

    /** Overview of all open findings, daily or weekly at 9:00 (Mondays). */
    private scheduleSummary(): void {
        const mode = this.config.summaryInterval;
        if (mode !== 'daily' && mode !== 'weekly') {
            return;
        }
        const next = new Date();
        next.setHours(9, 0, 0, 0);
        while (next.getTime() <= Date.now() || (mode === 'weekly' && next.getDay() !== 1)) {
            next.setDate(next.getDate() + 1);
        }
        this.summaryTimer = this.setTimeout(() => {
            void this.enqueue(async () => {
                await this.sendSummary();
            }).then(() => this.scheduleSummary());
        }, next.getTime() - Date.now());
    }

    private async sendSummary(): Promise<SendResult> {
        const open = this.store.open().sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
        const acked = this.store.all().filter(f => this.store.isAcked(f.id)).length;
        const m = summaryMessage(open, { score: this.store.score(), acked }, this.lang);
        return this.notifier.send(m.severity, m.title, m.text, true);
    }

    /** Reply for the settings page after sending a message. */
    private sendReply(res: SendResult, ok: string): { result?: string; error?: string } {
        if (res.sent) {
            return { result: res.errors.length ? `${ok}\n${res.errors.join('\n')}` : ok };
        }
        return {
            error: `${L(this.lang, 'Nicht verschickt', 'Not sent')}: ${res.errors.join('; ') || L(this.lang, 'kein Ziel', 'no target')}`,
        };
    }

    // ---------- persistence ----------

    private async readJson<T>(id: string): Promise<T | undefined> {
        const s = await this.getStateAsync(id);
        if (typeof s?.val !== 'string' || !s.val) {
            return undefined;
        }
        try {
            return JSON.parse(s.val) as T;
        } catch {
            return undefined;
        }
    }

    private async loadPersisted(): Promise<void> {
        const data = await this.readJson<{
            items: any[];
            acked: string[];
            initialized?: Category[];
            lang?: Lang;
            version?: string;
        }>('findings.json');
        this.store.load(data);
        this.initialized = new Set(Array.isArray(data?.initialized) ? data.initialized : []);
        if ((data?.lang && data.lang !== this.lang) || (data && data.version !== this.version)) {
            // texts change with the language or an update, that alone is no reason to notify again
            this.relabel = new Set(this.initialized);
        }
        const seen = await this.readJson<{ v?: number; seen?: SeenEvents }>('events.seen');
        if (seen) {
            this.eventsInitialized = true;
            if (seen.v === SEEN_FORMAT && seen.seen && typeof seen.seen === 'object' && !Array.isArray(seen.seen)) {
                this.seenEvents = seen.seen;
            } else {
                this.eventsSilent = true;
            }
        }
        const users = await this.readJson<unknown>('settings.knownUsers');
        this.knownUsers = Array.isArray(users) && users.every(u => typeof u === 'string') ? users : undefined;
        const up = await this.getStateAsync('info.uptime');
        this.lastUptime = typeof up?.val === 'number' ? up.val : undefined;
    }

    private async saveFindings(): Promise<void> {
        this.store.pruneAcks();
        const dump = {
            ...this.store.dump(),
            initialized: [...this.initialized],
            lang: this.lang,
            version: this.version,
        };
        await this.setState('findings.json', JSON.stringify(dump), true);
        const open = this.store.open();
        await this.setState('findings.open', open.length, true);
        await this.setState('findings.critical', open.filter(f => f.severity === 'critical').length, true);
        await this.setState('summary.score', this.store.score(), true);
        await this.setState('summary.text', this.summaryText(), true);
    }

    private summaryText(): string {
        const open = this.store.open();
        if (!open.length) {
            return L(this.lang, 'Keine offenen Punkte.', 'Nothing open.');
        }
        const icon: Record<Severity, string> = { critical: '🔴', warning: '🟠', info: '🔵' };
        return open
            .map(
                f =>
                    `${icon[f.severity]} ${f.title}${f.ackable ? `\n   ${L(this.lang, 'Bestätigen mit ID', 'Confirm with id')}: ${f.id}` : ''}`,
            )
            .join('\n');
    }

    // ---------- scheduling ----------

    /**
     * TR-064 calls are serialized, the box does not like parallel logins.
     */
    private enqueue(fn: () => Promise<void>, key?: string): Promise<void> {
        if (key) {
            if (this.pending.has(key)) {
                this.log.debug(`${key} is already waiting, skipped`);
                return Promise.resolve();
            }
            this.pending.add(key);
        }
        return this.queued(async () => {
            if (key) {
                this.pending.delete(key);
            }
            await fn();
        }).catch(() => undefined);
    }

    /** Like enqueue, but hands the result or the error to the caller as well. */
    private queued<T>(fn: () => Promise<T>): Promise<T> {
        const job = this.queue.then(() => (this.stopping ? Promise.reject(new Error('Adapter is stopping')) : fn()));
        this.queue = job.then(
            () => undefined,
            e => this.handleError(e as Error).catch(err => this.log.error(`Error handling failed: ${err}`)),
        );
        return job;
    }

    private async runAll(): Promise<void> {
        await this.enqueue(async () => {
            await this.runEvents();
            await this.runPorts();
            await this.runSettings();
            await this.runFirmware();
            await this.setState('info.lastRun', Date.now(), true);
        }, 'all');
    }

    private async getClient(): Promise<Tr064Client | undefined> {
        if (this.blocked) {
            return undefined;
        }
        if (!this.client) {
            const pin = await this.getStateAsync('info.certFingerprint');
            const client = new Tr064Client({
                host: this.config.host.trim(),
                username: this.config.username,
                password: this.config.password,
                useTls: this.config.useTls !== false,
                pinnedFingerprint: typeof pin?.val === 'string' ? pin.val : undefined,
            });
            const desc = await client.connect();
            await this.setState('info.model', desc.modelName, true);
            this.client = client;
        }
        return this.client;
    }

    private async afterCall(): Promise<void> {
        // the client pins the first certificate it sees, so store exactly that one
        const fp = this.client?.pinnedFingerprint;
        if (fp) {
            const pin = await this.getStateAsync('info.certFingerprint');
            if (!pin?.val) {
                // trust on first use
                await this.setState('info.certFingerprint', fp, true);
                this.log.info('Stored the TLS certificate fingerprint of the FRITZ!Box.');
            } else if (pin.val !== fp) {
                throw new CertificateMismatchError(String(pin.val), fp);
            }
        }
        await this.setStateChangedAsync('info.connection', true, true);
        if (this.failedRuns) {
            this.log.info('FRITZ!Box reachable again.');
        }
        this.failedRuns = 0;
        if (this.outageNotified) {
            this.outageNotified = false;
            await this.notifier.send(
                'info',
                L(this.lang, 'FRITZ!Box wieder erreichbar', 'FRITZ!Box reachable again'),
                L(this.lang, 'Die Überwachung läuft wieder.', 'Monitoring is running again.'),
                true,
            );
        }
    }

    private async handleError(err: Error): Promise<void> {
        if (this.stopping) {
            return;
        }
        await this.setStateChangedAsync('info.connection', false, true);
        this.client?.close();
        this.client = undefined;
        if (err instanceof CertificateMismatchError) {
            this.blocked = true;
            this.log.error(
                `The TLS certificate of the FRITZ!Box changed. No more logins until you confirm it in the settings. New fingerprint: ${err.actual}`,
            );
            await this.notifier.send(
                'critical',
                L(this.lang, 'Zertifikat der FRITZ!Box hat sich geändert', 'FRITZ!Box certificate changed'),
                L(
                    this.lang,
                    'Das kann nach einem Reset oder Firmware-Update normal sein, aber auch ein Angriff im Heimnetz. Der Adapter meldet sich nicht mehr an, bis du das neue Zertifikat in den Einstellungen bestätigst.',
                    'This can be normal after a reset or firmware update, but can also be an attack on your network. The adapter stops logging in until you confirm the new certificate in the settings.',
                ),
                true,
            );
        } else if (err instanceof AuthError) {
            // stop here, otherwise the adapter itself produces failed logins every few minutes
            this.blocked = true;
            this.log.error(`${err.message}. Polling stopped, please check the settings.`);
            await this.notifier.send(
                'critical',
                L(this.lang, 'FRITZ!Box lehnt die Anmeldung ab', 'FRITZ!Box rejects the login'),
                L(
                    this.lang,
                    'Die Überwachung ist angehalten. Wurde das Kennwort oder der Benutzer des Adapters auf der Box geändert oder gelöscht? Warst du das nicht, kann das auch ein Angreifer gewesen sein, der den Wächter abschalten will. Nach dem Korrigieren in den Einstellungen läuft der Adapter wieder an.',
                    'Monitoring has stopped. Was the password or the user of the adapter changed or deleted on the box? If it was not you, it may also be an attacker trying to switch off the guard. After fixing it in the settings the adapter starts again.',
                ),
                true,
            );
        } else {
            this.failedRuns++;
            if (!isNetworkError(err)) {
                // a bug or unexpected answer, not an outage: keep the stack for bug reports
                this.log.error(`Check failed: ${err.stack ?? err.message}`);
            } else if (this.failedRuns === 1) {
                // warn once per outage, not every few minutes
                this.log.warn(`FRITZ!Box not reachable: ${err.message}`);
            } else {
                this.log.debug(`FRITZ!Box still not reachable (${this.failedRuns}): ${err.message}`);
            }
            if (this.failedRuns === OUTAGE_RUNS && !this.outageNotified) {
                this.outageNotified = true;
                await this.notifier.send(
                    'warning',
                    L(this.lang, 'FRITZ!Box nicht erreichbar', 'FRITZ!Box not reachable'),
                    L(
                        this.lang,
                        `Die letzten ${OUTAGE_RUNS} Prüfungen sind gescheitert, die Box wird gerade nicht überwacht. Letzter Fehler: ${err.message}`,
                        `The last ${OUTAGE_RUNS} checks failed, the box is not being monitored right now. Last error: ${err.message}`,
                    ),
                    true,
                );
            }
        }
    }

    private ctx(client: Tr064Client): CheckContext {
        return { client, lang: this.lang, log: this.log };
    }

    // ---------- checks ----------

    private async runEvents(): Promise<void> {
        const client = await this.getClient();
        if (!client) {
            return;
        }
        const ctx = this.ctx(client);
        // the provider may change the prefix any time, so learn it again on every run
        learnHomeIpv6(
            Object.values(networkInterfaces())
                .flat()
                .map(i => i?.address ?? ''),
        );
        const events = await readDeviceLog(ctx);
        await this.afterCall();
        if (!events.length) {
            // nothing readable: keep what was seen, otherwise the next read reports the whole log again
            return;
        }

        const picked = freshEvents(events, this.seenEvents);
        const fresh = this.eventsSilent ? [] : picked.fresh;
        this.eventsSilent = false;
        this.seenEvents = picked.seen;
        await this.setState('events.seen', JSON.stringify({ v: SEEN_FORMAT, seen: this.seenEvents }), true);

        const dayAgo = Date.now() - 24 * 60 * MIN;
        const failed = events.filter(e => e.kind === 'login-failed' || e.kind === 'login-blocked');
        await this.setState(
            'events.failedLogins24h',
            failed.filter(e => (e.time?.getTime() ?? 0) >= dayAgo).reduce((n, e) => n + e.count, 0),
            true,
        );
        if (failed[0]) {
            const f = failed[0];
            await this.setState(
                'events.lastFailedLogin',
                JSON.stringify({
                    time: f.time?.toISOString() ?? f.rawTime,
                    ip: f.ip,
                    user: f.user,
                    channel: f.channel,
                    message: f.message,
                }),
                true,
            );
        }

        const skipKnownPrivate = this.config.skipKnownPrivate !== false;
        const needHosts = this.config.alertNewDevices && skipKnownPrivate && fresh.some(e => e.kind === 'new-device');
        const hosts = needHosts ? await readHosts(ctx) : undefined;
        const alerts = evaluateEvents(
            fresh,
            {
                ownUser: this.config.username,
                knownIps: parseIpList(this.config.knownIps ?? ''),
                alertRemoteLogins: this.config.alertRemoteLogins !== false,
                alertNewDevices: !!this.config.alertNewDevices,
                skipKnownPrivate,
                hosts,
                attackThreshold: Number(this.config.attackThreshold) || 5,
            },
            this.lang,
        );

        if (!this.eventsInitialized) {
            this.eventsInitialized = true;
            if (alerts.length) {
                const worst = alerts.reduce((a, b) => (SEVERITY_RANK[b.severity] > SEVERITY_RANK[a.severity] ? b : a));
                await this.notifier.send(
                    worst.severity,
                    L(this.lang, 'Ereignisprotokoll: erste Auswertung', 'Event log: first check'),
                    alerts.map(a => `• ${a.title}\n${a.text}`).join('\n\n'),
                );
            }
            return;
        }
        for (const a of alerts) {
            await this.notifier.send(a.severity, a.title, a.text);
        }
    }

    private async runPorts(): Promise<void> {
        const client = await this.getClient();
        if (!client) {
            return;
        }
        const res = await checkExposure(this.ctx(client), this.config.portSelfTest !== false);
        await this.afterCall();
        await this.setState('ports.json', JSON.stringify(res.ports), true);
        await this.setState('ports.wanIp', res.wanIp ?? '', true);
        await this.applyFindings('ports', res.findings);
    }

    private async runSettings(): Promise<void> {
        const client = await this.getClient();
        if (!client) {
            return;
        }
        const res = await checkSettings(this.ctx(client), this.knownUsers, this.config.username);
        await this.afterCall();
        if (!this.knownUsers && res.users) {
            this.knownUsers = res.users;
            await this.setState('settings.knownUsers', JSON.stringify(res.users), true);
        }
        await this.applyFindings('settings', res.findings);
    }

    private async runFirmware(): Promise<void> {
        const client = await this.getClient();
        if (!client) {
            return;
        }
        const res = await checkFirmware(this.ctx(client), {
            vendorCheck: !!this.config.vendorFirmwareCheck,
            ageDays: id => {
                const f = this.store.all().find(x => x.id === id);
                return f ? Math.floor((Date.now() - f.firstSeen) / (24 * 60 * MIN)) : 0;
            },
        });
        await this.afterCall();
        const i = res.info;
        await this.setState('firmware.installed', i.installed, true);
        await this.setState('firmware.updateAvailable', i.updateAvailable, true);
        await this.setState('firmware.availableVersion', i.availableVersion ?? '', true);
        await this.setState('firmware.vendorLatest', i.vendorLatest ?? '', true);
        if (i.uptime !== undefined) {
            if (this.lastUptime !== undefined && i.uptime < this.lastUptime) {
                await this.notifier.send(
                    'info',
                    L(this.lang, 'FRITZ!Box wurde neu gestartet', 'FRITZ!Box was restarted'),
                    L(
                        this.lang,
                        'Dabei wurde auch das Ereignisprotokoll geleert. Warst du das nicht, lohnt ein Blick auf die Einstellungen.',
                        'This also cleared the event log. If it was not you, have a look at the settings.',
                    ),
                );
            }
            this.lastUptime = i.uptime;
            await this.setState('info.uptime', i.uptime, true);
        }
        await this.applyFindings('firmware', res.findings);
    }

    /**
     * Stores findings of a category and notifies about what is new or changed.
     */
    private async applyFindings(category: Category, findings: Finding[]): Promise<void> {
        const diff = this.store.update(category, findings);
        if (this.relabel.delete(category)) {
            diff.changed = [];
        }
        const first = !this.initialized.has(category);
        this.initialized.add(category);
        await this.saveFindings();
        await this.notifyDiff(category, diff, first);
    }

    private async notifyDiff(category: Category, diff: Diff, first: boolean): Promise<void> {
        const relevant = [...diff.added, ...diff.changed].filter(f => !this.store.isAcked(f.id));
        const hint = (ackable?: boolean, id?: string): string =>
            ackable ? `\n\n${L(this.lang, 'Gewollt? Dann bestätigen mit', 'Intended? Confirm with')}: ${id}` : '';

        if (first && relevant.length) {
            const worst = relevant.reduce((a, b) => (SEVERITY_RANK[b.severity] > SEVERITY_RANK[a.severity] ? b : a));
            const names: Record<Category, string> = {
                ports: L(this.lang, 'Offene Ports', 'Open ports'),
                settings: L(this.lang, 'Einstellungen', 'Settings'),
                firmware: 'Firmware',
                connection: L(this.lang, 'Verbindung', 'Connection'),
            };
            await this.notifier.send(
                worst.severity,
                `${names[category]}: ${L(this.lang, 'erste Prüfung', 'first check')}`,
                relevant.map(f => `• ${f.title}\n${f.detail}${hint(f.ackable, f.id)}`).join('\n\n'),
            );
            return;
        }
        for (const f of relevant) {
            await this.notifier.send(
                f.severity,
                f.title,
                `${f.detail}${f.advice ? `\n\n${f.advice}` : ''}${hint(f.ackable, f.id)}`,
            );
        }
        if (this.config.notifyResolved) {
            for (const f of diff.resolved) {
                await this.notifier.send(f.severity, `${L(this.lang, 'Erledigt', 'Resolved')}: ${f.title}`, '');
            }
        }
    }

    // ---------- user interaction ----------

    private async onStateChange(id: string, state: ioBroker.State | null | undefined): Promise<void> {
        if (!state || state.ack) {
            return;
        }
        const short = id.slice(this.namespace.length + 1);
        if (short === 'actions.runNow') {
            await this.setState(short, false, true);
            if (!this.config.host || !this.config.username || !this.config.password) {
                this.log.info('Run now ignored: the setup is not finished yet.');
                return;
            }
            this.blocked = false;
            await this.runAll();
        } else if (short === 'findings.acknowledge' || short === 'findings.unacknowledge') {
            const fid = String(state.val ?? '').trim();
            if (fid && !(await this.setAck(fid, short === 'findings.acknowledge'))) {
                this.log.warn(`Cannot confirm "${fid}": unknown id or not confirmable`);
            }
            await this.setState(short, '', true);
        }
    }

    /** Confirms a finding as intended (or undoes that). Returns false for unknown ids. */
    private async setAck(fid: string, on: boolean): Promise<boolean> {
        if (on) {
            if (!this.store.acknowledge(fid)) {
                return false;
            }
            if (fid.startsWith('user:') && this.knownUsers) {
                this.knownUsers = [...new Set([...this.knownUsers, fid.slice(5)])];
                await this.setState('settings.knownUsers', JSON.stringify(this.knownUsers), true);
            }
        } else {
            this.store.unacknowledge(fid);
        }
        await this.saveFindings();
        return true;
    }

    /**
     * Findings for the settings page.
     *
     * @param pending ticks from the (maybe unsaved) table in the settings, they win over the stored state
     */
    private findingsText(pending?: Record<string, boolean>): string {
        const isAcked = (id: string): boolean => pending?.[id] ?? this.store.isAcked(id);
        const all = this.store.all().sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
        const open = all.filter(f => !f.ackable || !isAcked(f.id));
        const acked = all.filter(f => f.ackable && isAcked(f.id));
        const unsaved = all.some(f => f.ackable && isAcked(f.id) !== this.store.isAcked(f.id));
        if (!all.length) {
            return L(
                this.lang,
                'Noch keine Ergebnisse. Ist die Verbindung eingerichtet? Der erste Lauf dauert ein paar Sekunden.',
                'No results yet. Is the connection set up? The first run takes a few seconds.',
            );
        }
        return findingsHtml(open, { score: this.store.score(), acked: acked.length }, this.lang, {
            acked,
            unsaved,
            emptyTable: pending !== undefined && !Object.keys(pending).length && open.some(f => f.ackable),
        });
    }

    /** Last diagnostics report for the settings page, with a link to the state. */
    private async diagnosticsHtml(): Promise<string> {
        const st = await this.getStateAsync('info.diagnostics');
        const id = `${this.namespace}.info.diagnostics`;
        if (!st?.val) {
            return L(this.lang, 'Noch keine Diagnose gelaufen.', 'No diagnostics run yet.');
        }
        const when = new Date(st.ts).toLocaleString(this.lang === 'de' ? 'de-DE' : 'en-GB');
        return `<div>${L(this.lang, 'Stand', 'As of')}: ${esc(when)} · ${L(this.lang, 'Datenpunkt', 'State')} <a style="color:#4fa3ff;text-decoration:underline" href="#tab-objects/${esc(id)}">${esc(id)}</a></div><pre style="max-height:450px;overflow:auto;white-space:pre-wrap;font-size:12px;padding:8px;border:1px solid rgba(128,128,128,.4)">${esc(String(st.val))}</pre>`;
    }

    /** Rows for the confirmation table in the settings. */
    private confirmationRows(): ConfirmationRow[] {
        return this.store
            .all()
            .filter(f => f.ackable)
            .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])
            .map(f => ({ id: f.id, title: `${SEVERITY_ICON[f.severity]} ${f.title}`, ok: this.store.isAcked(f.id) }));
    }

    /**
     * Applies the ticks saved in the settings table. Only rows the user changed since the
     * last time count, so a confirmation made via state or Telegram is not undone by an old table.
     */
    private async applyConfirmations(): Promise<void> {
        const rows = Array.isArray(this.config.confirmations) ? this.config.confirmations : [];
        const last = (await this.readJson<Record<string, boolean>>('findings.confirmationsApplied')) ?? {};
        const now: Record<string, boolean> = {};
        for (const r of rows) {
            if (!r?.id) {
                continue;
            }
            const ok = !!r.ok;
            now[r.id] = ok;
            if (last[r.id] !== ok && this.store.isAcked(r.id) !== ok) {
                await this.setAck(r.id, ok);
            }
        }
        await this.setState('findings.confirmationsApplied', JSON.stringify(now), true);
    }

    private async onMessage(obj: ioBroker.Message): Promise<void> {
        if (!obj?.command) {
            if (obj?.callback && obj.from) {
                this.sendTo(obj.from, '', { error: 'No command' }, obj.callback);
            }
            return;
        }
        const reply = (res: unknown): void => {
            if (obj.callback) {
                this.sendTo(obj.from, obj.command, res, obj.callback);
            }
        };
        const data = (typeof obj.message === 'object' && obj.message) || {};
        try {
            switch (obj.command) {
                case 'discover': {
                    const boxes = await discoverBoxes(this);
                    if (!boxes.length) {
                        reply({
                            error: L(
                                this.lang,
                                'Keine FRITZ!Box gefunden. Adresse bitte von Hand eintragen.',
                                'No FRITZ!Box found. Please enter the address manually.',
                            ),
                        });
                    } else {
                        const b = boxes.find(x => x.host !== 'fritz.box') ?? boxes[0];
                        reply({
                            native: { host: b.host },
                            result: boxes.map(x => `${x.model} (FRITZ!OS ${x.firmware}) - ${x.host}`).join('\n'),
                        });
                    }
                    break;
                }
                case 'testConnection': {
                    reply(await this.testConnection(data));
                    break;
                }
                case 'testNotify': {
                    const n = new Notifier(this, {
                        telegramEnabled: !!data.telegramEnabled,
                        telegramInstance: String(data.telegramInstance ?? ''),
                        telegramUser: String(data.telegramUser ?? ''),
                        emailEnabled: !!data.emailEnabled,
                        emailInstance: String(data.emailInstance ?? ''),
                        emailTo: String(data.emailTo ?? ''),
                        minSeverity: 'info',
                    });
                    if (!n.configured) {
                        reply({ error: L(this.lang, 'Kein Ziel ausgewählt.', 'No target selected.') });
                        break;
                    }
                    const res = await n.send(
                        'info',
                        'fb-guard',
                        L(
                            this.lang,
                            'Testnachricht: Benachrichtigungen funktionieren.',
                            'Test message: notifications work.',
                        ),
                        true,
                    );
                    reply(this.sendReply(res, L(this.lang, 'Testnachricht wurde verschickt.', 'Test message sent.')));
                    break;
                }
                case 'diagnose': {
                    // through the queue, so it never logs in while a check is running
                    const done = await this.queued(async () => {
                        const client = await this.getClient();
                        if (!client) {
                            return false;
                        }
                        const report = await runDiagnostics(client);
                        await this.afterCall();
                        await this.setState('info.diagnostics', JSON.stringify(report, null, 1), true);
                        return true;
                    });
                    // changing the stamp makes the report view below the button reload
                    reply(
                        done
                            ? { native: { _diagStamp: Date.now() } }
                            : { error: L(this.lang, 'Keine Verbindung zur Box.', 'Not connected to the box.') },
                    );
                    break;
                }
                case 'diagnosticsText': {
                    reply({ text: await this.diagnosticsHtml() });
                    break;
                }
                case 'devicesInfo': {
                    if (this.devicesCache && Date.now() - this.devicesCache.at < 10 * MIN) {
                        reply({ text: this.devicesCache.html });
                        break;
                    }
                    const html = await this.queued(async () => {
                        const client = await this.getClient();
                        if (!client) {
                            return undefined;
                        }
                        const hosts = await readHosts(this.ctx(client));
                        await this.afterCall();
                        return esc(describeHosts(hosts, this.lang)).replace(/\n/g, '<br>');
                    });
                    if (html === undefined) {
                        reply({ text: L(this.lang, 'Keine Verbindung zur Box.', 'Not connected to the box.') });
                        break;
                    }
                    this.devicesCache = { at: Date.now(), html };
                    reply({ text: html });
                    break;
                }
                case 'sendSummary': {
                    if (!this.notifier.configured) {
                        reply({
                            error: L(
                                this.lang,
                                'Keine Benachrichtigung eingerichtet (erst speichern).',
                                'No notification set up (save first).',
                            ),
                        });
                        break;
                    }
                    const rows = Array.isArray(data.confirmations) ? (data.confirmations as ConfirmationRow[]) : [];
                    if (rows.some(r => r?.id && !!r.ok !== this.store.isAcked(r.id))) {
                        reply({
                            error: L(
                                this.lang,
                                'Du hast Haken geändert, aber noch nicht gespeichert. Bitte erst unten auf "Speichern" klicken, sonst enthält die Übersicht noch den alten Stand.',
                                'You changed ticks but did not save yet. Please click "Save" first, otherwise the overview still shows the old state.',
                            ),
                        });
                        break;
                    }
                    reply(
                        this.sendReply(
                            await this.sendSummary(),
                            L(this.lang, 'Übersicht wurde verschickt.', 'Overview sent.'),
                        ),
                    );
                    break;
                }
                case 'findingsText': {
                    const rows = Array.isArray(data.confirmations) ? (data.confirmations as ConfirmationRow[]) : [];
                    const pending = Object.fromEntries(rows.filter(r => r?.id).map(r => [r.id, !!r.ok]));
                    reply({ text: this.findingsText(pending) });
                    break;
                }
                case 'loadConfirmations': {
                    const rows = this.confirmationRows();
                    if (!rows.length) {
                        reply({
                            error: L(
                                this.lang,
                                'Keine bestätigbaren Funde. Läuft der Adapter?',
                                'No findings to confirm. Is the adapter running?',
                            ),
                        });
                        break;
                    }
                    reply({ native: { confirmations: rows } });
                    break;
                }
                case 'acknowledge':
                case 'unacknowledge': {
                    const fid = String(data.id ?? '').trim();
                    if (!fid) {
                        reply({
                            error: L(this.lang, 'Bitte zuerst einen Fund auswählen.', 'Please select a finding first.'),
                        });
                    } else if (!(await this.setAck(fid, obj.command === 'acknowledge'))) {
                        reply({ error: L(this.lang, 'Unbekannter Fund.', 'Unknown finding.') });
                    } else {
                        reply({
                            result: L(
                                this.lang,
                                'Gespeichert. Die Liste aktualisiert sich beim nächsten Öffnen der Einstellungen.',
                                'Saved. The list updates the next time you open the settings.',
                            ),
                        });
                    }
                    break;
                }
                case 'trustCertificate': {
                    await this.setState('info.certFingerprint', '', true);
                    this.blocked = false;
                    this.client?.close();
                    this.client = undefined;
                    reply({
                        result: L(
                            this.lang,
                            'Das aktuelle Zertifikat wird bei der nächsten Verbindung übernommen.',
                            'The current certificate will be trusted on the next connection.',
                        ),
                    });
                    break;
                }
                default:
                    reply({ error: `Unknown command ${obj.command}` });
            }
        } catch (e) {
            reply({ error: (e as Error).message });
        }
    }

    private async testConnection(data: Record<string, any>): Promise<{ result?: string; error?: string }> {
        const host = String(data.host ?? '').trim();
        if (!host || !data.username || !data.password) {
            return {
                error: L(
                    this.lang,
                    'Bitte Adresse, Benutzer und Kennwort ausfüllen.',
                    'Please fill in address, user and password.',
                ),
            };
        }
        const pin = await this.getStateAsync('info.certFingerprint');
        const client = new Tr064Client({
            host,
            username: String(data.username),
            password: String(data.password),
            useTls: data.useTls !== false,
            pinnedFingerprint: host === this.config.host && typeof pin?.val === 'string' ? pin.val : undefined,
        });
        try {
            const desc = await client.connect();
            const me = await client.call('LANConfigSecurity:1', 'X_AVM-DE_GetCurrentUser');
            const rights = me['NewX_AVM-DE_CurrentUserRights'] ?? '';
            const hasSettings =
                /BoxAdmin[^]*?readwrite|BoxAdmin[^]*?readonly/i.test(rights) || /einstellungen/i.test(rights);
            const lines = [
                `${desc.modelName}, FRITZ!OS ${desc.firmware}`,
                L(this.lang, 'Anmeldung erfolgreich.', 'Login successful.'),
                data.useTls !== false
                    ? L(this.lang, 'Verbindung verschlüsselt (TLS).', 'Connection encrypted (TLS).')
                    : L(this.lang, 'Achtung: Verbindung unverschlüsselt.', 'Warning: connection not encrypted.'),
                hasSettings
                    ? L(this.lang, 'Rechte: ausreichend.', 'Rights: sufficient.')
                    : L(
                          this.lang,
                          'Rechte: bitte dem Benutzer das Recht "FRITZ!Box Einstellungen" geben.',
                          'Rights: please grant the user the "FRITZ!Box settings" right.',
                      ),
            ];
            return { result: lines.join('\n') };
        } catch (e) {
            const err = e as Error;
            if (err instanceof AuthError) {
                return {
                    error: L(
                        this.lang,
                        'Anmeldung abgelehnt: Benutzer oder Kennwort falsch. Achtung, die Box sperrt nach mehreren Fehlversuchen kurz.',
                        'Login rejected: wrong user or password. Note that the box blocks briefly after several failures.',
                    ),
                };
            }
            if (err instanceof CertificateMismatchError) {
                return {
                    error: L(
                        this.lang,
                        'Das Zertifikat der Box hat sich geändert. Bitte unten "Zertifikat neu übernehmen" nutzen, wenn das erwartet war.',
                        'The certificate changed. Use "Trust certificate again" below if this was expected.',
                    ),
                };
            }
            return { error: err.message };
        } finally {
            client.close();
        }
    }

    private onUnload(callback: () => void): void {
        try {
            this.stopping = true;
            for (const t of this.timers) {
                this.clearInterval(t);
            }
            if (this.summaryTimer) {
                this.clearTimeout(this.summaryTimer);
            }
            this.client?.close();
            callback();
        } catch {
            callback();
        }
    }
}

if (require.main !== module) {
    module.exports = (options: Partial<utils.AdapterOptions> | undefined) => new FbGuard(options);
} else {
    (() => new FbGuard())();
}
