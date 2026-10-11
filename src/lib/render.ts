import type { Finding, Severity } from './findings';
import type { Lang } from './knowledge/ports';

export const ICON: Record<Severity, string> = { critical: '🔴', warning: '🟠', info: '🔵' };

/**
 * Escapes text for HTML. Everything that comes from the box (names, descriptions, log lines)
 * must go through here, a UPnP device can set any forwarding description it likes.
 */
export function esc(s: string | undefined): string {
    return String(s ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

const lines = (s: string): string => esc(s).replace(/\n/g, '<br>');

/**
 * Renders the findings for the settings page: one expandable entry per finding.
 */
export function findingsHtml(
    open: Finding[],
    stats: { score: number; acked: number },
    lang: Lang,
    extra: { acked?: Finding[]; unsaved?: boolean; emptyTable?: boolean } = {},
): string {
    const de = lang === 'de';
    let head = de
        ? `<b>Sicherheitswert ${stats.score} von 100</b> · ${open.length} offen · ${stats.acked} als gewollt bestätigt`
        : `<b>Security score ${stats.score} of 100</b> · ${open.length} open · ${stats.acked} confirmed as intended`;
    if (extra.unsaved) {
        head += `<div style="color:orange">${
            de
                ? 'Geänderte Haken in der Tabelle unten. Wirksam nach dem Speichern, der Sicherheitswert wird dann neu berechnet.'
                : 'Changed ticks in the table below. They take effect after saving, the score is recalculated then.'
        }</div>`;
    }
    if (extra.emptyTable) {
        head += `<div style="margin-top:4px">${
            de
                ? 'Etwas davon ist gewollt? Unten unter "Als gewollt bestätigen" die Funde in die Tabelle holen und abhaken.'
                : 'Something here is intended? Fetch the findings into the table below under "Confirm as intended" and tick them.'
        }</div>`;
    }
    const ackedList = extra.acked?.length
        ? `<details style="margin:10px 0;opacity:.75"><summary style="cursor:pointer">✔ ${
              de ? 'Als gewollt bestätigt' : 'Confirmed as intended'
          } (${extra.acked.length})</summary><ul style="margin:4px 0">${extra.acked
              .map(f => `<li>${esc(f.title)}</li>`)
              .join('')}</ul></details>`
        : '';
    if (!open.length) {
        return `<div>${head}</div><p>${de ? 'Keine offenen Funde.' : 'No open findings.'}</p>${ackedList}`;
    }
    const items = open.map(f => {
        const body = [
            `<div>${lines(f.detail)}</div>`,
            f.advice ? `<div style="margin-top:4px">→ ${lines(f.advice)}</div>` : '',
            f.more ? `<div style="margin-top:6px;opacity:.85">${lines(f.more)}</div>` : '',
            `<div style="margin-top:6px;font-size:smaller;opacity:.6">ID: ${esc(f.id)}</div>`,
        ].join('');
        return `<details style="margin:6px 0"><summary style="cursor:pointer">${ICON[f.severity]} ${esc(f.title)}</summary><div style="padding:4px 0 8px 22px">${body}</div></details>`;
    });
    return `<div>${head}</div><div style="font-size:smaller;opacity:.7;margin:4px 0 8px">${
        de ? 'Zum Aufklappen auf einen Eintrag klicken.' : 'Click an entry to expand it.'
    }</div>${items.join('')}${ackedList}`;
}

/**
 * Overview of all open findings for Telegram/e-mail, grouped by severity. Plain text,
 * the notifier escapes it.
 */
export function summaryMessage(
    open: Finding[],
    stats: { score: number; acked: number },
    lang: Lang,
): { severity: Severity; title: string; text: string } {
    const de = lang === 'de';
    const groups: [Severity, string][] = [
        ['critical', de ? 'Kritisch' : 'Critical'],
        ['warning', de ? 'Warnungen' : 'Warnings'],
        ['info', de ? 'Hinweise' : 'Notes'],
    ];
    const parts = [
        de
            ? `Sicherheitswert ${stats.score} von 100\n${open.length} offen, ${stats.acked} als gewollt bestätigt`
            : `Security score ${stats.score} of 100\n${open.length} open, ${stats.acked} confirmed as intended`,
    ];
    for (const [sev, name] of groups) {
        const list = open.filter(f => f.severity === sev);
        if (list.length) {
            parts.push(`${ICON[sev]} ${name} (${list.length})\n${list.map(f => `• ${f.title}`).join('\n')}`);
        }
    }
    if (!open.length) {
        parts.push(de ? 'Keine offenen Funde.' : 'No open findings.');
    }
    parts.push(
        de
            ? 'Erklärungen und Bestätigen: Adapter-Einstellungen, Reiter "Funde".'
            : 'Explanations and confirming: adapter settings, tab "Findings".',
    );
    const severity = groups.find(([sev]) => open.some(f => f.severity === sev))?.[0] ?? 'info';
    return { severity, title: de ? 'fb-guard: Übersicht' : 'fb-guard: overview', text: parts.join('\n\n') };
}
