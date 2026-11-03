import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// Not I18n from adapter-core: importing that package needs a js-controller, which would break the unit tests
const LANGUAGES = ['en', 'de', 'ru', 'pt', 'nl', 'fr', 'it', 'es', 'pl', 'uk', 'zh-cn'];

let language = 'en';
let words: Record<string, string> = {};

/**
 * Loads the translations from admin/i18n for the given system language. Unknown languages fall back to English.
 *
 * @param lang language from system.config
 */
export function initI18n(lang: string): void {
    language = LANGUAGES.includes(lang) ? lang : 'en';
    const file = join(__dirname, '..', '..', 'admin', 'i18n', `${language}.json`);
    words = JSON.parse(readFileSync(file, 'utf8'));
}

/**
 * Translates a text into the system language. The key is the English text, %s stands for an argument.
 *
 * @param key English text
 * @param args values for %s, in order
 */
export function t(key: string, ...args: (string | number)[]): string {
    let i = 0;
    return (words[key] ?? key).replace(/%s/g, () => String(args[i++] ?? ''));
}

/** Locale for formatting dates in the system language. */
export function locale(): string {
    if (language === 'zh-cn') {
        return 'zh-CN';
    }
    return language === 'en' ? 'en-GB' : language;
}
