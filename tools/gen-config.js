// Generates admin/jsonConfig.json and admin/i18n/*.json. Usage: node tools/gen-config.js .
const fs = require('fs');
const path = require('path');
const dir = process.argv[2];
const T = [];
const t = (en, de) => { T.push([en, de]); return en; };
const J = f => '${JSON.stringify(data.' + f + ')}';
const send = (command, label, fields, extra = {}) => ({
    type: 'sendTo', command, label, variant: 'contained', showProcess: true,
    jsonData: '{' + fields.map(f => `"${f}": ${J(f)}`).join(', ') + '}',
    xs: 12, sm: 6, md: 4, newLine: true, ...extra,
});
const txt = (en, de, extra = {}) => ({ type: 'staticText', text: t(en, de), xs: 12, newLine: true, ...extra });
const hdr = (en, de) => ({ type: 'header', text: t(en, de), size: 3, newLine: true });
let n = 0;
const k = p => `_${p}${++n}`;
const small = { style: { fontSize: 'smaller' } };

const tabs = {
    welcome: { type: 'panel', label: t('1. Welcome', '1. Willkommen'), items: {
        [k('h')]: hdr('What this adapter does', 'Was dieser Adapter macht'),
        [k('t')]: txt('fb-guard regularly checks your FRITZ!Box for failed logins, open ports, outdated firmware and weak settings, and tells you via Telegram or e-mail.',
            'fb-guard prüft deine FRITZ!Box regelmäßig auf fehlgeschlagene Anmeldungen, offene Ports, veraltete Firmware und unsichere Einstellungen und meldet sich per Telegram oder E-Mail.'),
        [k('t')]: txt('It only reads. It does not change anything on the box and only talks to your own box. External services stay off unless you switch them on.',
            'Der Adapter liest nur. Er ändert nichts an der Box und spricht nur mit deiner eigenen Box. Externe Dienste bleiben aus, solange du sie nicht einschaltest.'),
        [k('t')]: txt('Go through the tabs from left to right. Every step has a test button.', 'Geh die Reiter von links nach rechts durch. Jeder Schritt hat einen Test-Knopf.'),
        [k('t')]: txt('Tip: open the ioBroker admin via HTTPS, then your entries are encrypted on the way to the server as well. The password is stored encrypted.',
            'Tipp: Öffne den ioBroker-Admin über HTTPS, dann sind deine Eingaben auch auf dem Weg zum Server verschlüsselt. Gespeichert wird das Kennwort verschlüsselt.'),
        [k('h')]: hdr('Disclaimer', 'Hinweis'),
        [k('t')]: txt('fb-guard is an independent open-source project. It is not affiliated with, endorsed or supported by FRITZ! GmbH (formerly AVM). FRITZ! and FRITZ!Box are trademarks of FRITZ! GmbH and are only used to name the supported device.',
            'fb-guard ist ein unabhängiges Open-Source-Projekt. Es steht in keiner Verbindung zur FRITZ! GmbH (ehemals AVM) und wird von ihr weder unterstützt noch geprüft. FRITZ! und FRITZ!Box sind Marken der FRITZ! GmbH und werden nur zur Bezeichnung des unterstützten Geräts genannt.'),
        [k('t')]: txt('No guarantee: the adapter helps you spot problems, but it cannot make your network secure on its own. Use at your own risk.',
            'Keine Garantie: Der Adapter hilft, Probleme zu erkennen, macht dein Netz aber nicht von allein sicher. Nutzung auf eigenes Risiko.', small),
    } },
    box: { type: 'panel', label: t('2. Connect box', '2. Box verbinden'), items: {
        [k('h')]: hdr('Find the box', 'Box finden'),
        host: { type: 'text', label: t('Address of the FRITZ!Box', 'Adresse der FRITZ!Box'), help: t('e.g. 192.168.178.1 or fritz.box', 'z. B. 192.168.178.1 oder fritz.box'), xs: 12, sm: 6, md: 4, newLine: true },
        _discover: { type: 'sendTo', command: 'discover', label: t('Search', 'Suchen'), variant: 'outlined', showProcess: true, useNative: true, xs: 12, sm: 6, md: 3 },
        [k('h')]: hdr('Create a user for the adapter', 'Benutzer für den Adapter anlegen'),
        [k('t')]: txt('Open the box in your browser: System > FRITZ!Box Users > Add User. Name it e.g. "fb-guard", choose a long password and grant only the right "FRITZ!Box Settings". Switch off "Access from the internet".',
            'Öffne die Box im Browser: System > FRITZ!Box-Benutzer > Benutzer hinzufügen. Name z. B. "fb-guard", ein langes Kennwort vergeben und nur das Recht "FRITZ!Box Einstellungen" geben. "Zugang auch aus dem Internet" ausschalten.'),
        [k('t')]: txt('Also check: Home Network > Network > Network Settings > "Allow access for applications" must be on.',
            'Außerdem: Heimnetz > Netzwerk > Netzwerkeinstellungen > "Zugriff für Anwendungen zulassen" muss an sein.'),
        username: { type: 'text', label: t('User', 'Benutzer'), xs: 12, sm: 6, md: 4, newLine: true },
        password: { type: 'password', label: t('Password', 'Kennwort'), repeat: false, visible: true, xs: 12, sm: 6, md: 4 },
        useTls: { type: 'checkbox', label: t('Encrypted connection (recommended)', 'Verschlüsselte Verbindung (empfohlen)'), xs: 12, newLine: true },
        _tlsOff: { ...txt('Without encryption the password crosses your network in an attackable form. Only switch off if the box cannot do it.',
            'Ohne Verschlüsselung geht das Kennwort in angreifbarer Form durchs Netz. Nur ausschalten, wenn die Box es nicht kann.'), hidden: '!!data.useTls', style: { color: 'orange' } },
        _test: send('testConnection', t('Test connection', 'Verbindung testen'), ['host', 'username', 'password', 'useTls']),
        _trust: { ...send('trustCertificate', t('Trust certificate again', 'Zertifikat neu übernehmen'), []), variant: 'outlined', newLine: false,
            confirm: { title: t('Trust new certificate?', 'Neues Zertifikat übernehmen?'), text: t('Only do this if you reset or updated the box.', 'Nur machen, wenn du die Box zurückgesetzt oder aktualisiert hast.'), ok: t('OK', 'OK'), cancel: t('Cancel', 'Abbrechen') } },
    } },
    notify: { type: 'panel', label: t('3. Notifications', '3. Benachrichtigungen'), items: {
        telegramEnabled: { type: 'checkbox', label: t('Telegram', 'Telegram'), xs: 12, newLine: true },
        telegramInstance: { type: 'instance', adapter: 'telegram', label: t('Telegram instance', 'Telegram-Instanz'), hidden: '!data.telegramEnabled', xs: 12, sm: 6, md: 4, newLine: true },
        telegramUser: { type: 'text', label: t('Recipient (empty = all)', 'Empfänger (leer = alle)'), hidden: '!data.telegramEnabled', xs: 12, sm: 6, md: 4 },
        emailEnabled: { type: 'checkbox', label: t('E-mail', 'E-Mail'), xs: 12, newLine: true },
        emailInstance: { type: 'instance', adapter: 'email', label: t('E-mail instance', 'E-Mail-Instanz'), hidden: '!data.emailEnabled', xs: 12, sm: 6, md: 4, newLine: true },
        emailTo: { type: 'text', label: t('Recipient (empty = default of the instance)', 'Empfänger (leer = Standard der Instanz)'), hidden: '!data.emailEnabled', xs: 12, sm: 6, md: 4 },
        minSeverity: { type: 'select', label: t('Notify from', 'Melden ab'), options: [
            { label: t('Info', 'Hinweis'), value: 'info' }, { label: t('Warning', 'Warnung'), value: 'warning' }, { label: t('Critical only', 'Nur kritisch'), value: 'critical' }], xs: 12, sm: 6, md: 4, newLine: true },
        notifyResolved: { type: 'checkbox', label: t('Also notify when something is resolved', 'Auch melden, wenn etwas erledigt ist'), xs: 12, sm: 6, md: 4 },
        summaryInterval: { type: 'select', label: t('Overview of all findings', 'Übersicht aller Funde'), options: [
            { label: t('Off', 'Aus'), value: 'off' }, { label: t('Daily at 9:00', 'Täglich um 9:00'), value: 'daily' }, { label: t('Mondays at 9:00', 'Montags um 9:00'), value: 'weekly' }],
            help: t('One message listing everything that is open, also findings below "Notify from".', 'Eine Nachricht mit allem, was offen ist, auch Funde unterhalb von "Melden ab".'), xs: 12, sm: 6, md: 4, newLine: true },
        _testNotify: send('testNotify', t('Send test message', 'Testnachricht senden'), ['telegramEnabled', 'telegramInstance', 'telegramUser', 'emailEnabled', 'emailInstance', 'emailTo']),
    } },
    checks: { type: 'panel', label: t('4. Checks', '4. Prüfungen'), items: {
        [k('h')]: hdr('Intervals (minutes)', 'Intervalle (Minuten)'),
        intervalEvents: { type: 'number', min: 1, max: 60, label: t('Event log', 'Ereignisprotokoll'), help: t('1 to 60, default 5', '1 bis 60, Standard 5'), xs: 12, sm: 6, md: 3, newLine: true },
        intervalPorts: { type: 'number', min: 15, max: 1440, label: t('Ports', 'Ports'), help: t('15 to 1440, default 60', '15 bis 1440, Standard 60'), xs: 12, sm: 6, md: 3 },
        intervalSettings: { type: 'number', min: 15, max: 1440, label: t('Settings', 'Einstellungen'), help: t('15 to 1440, default 60', '15 bis 1440, Standard 60'), xs: 12, sm: 6, md: 3 },
        intervalFirmware: { type: 'number', min: 60, max: 10080, label: t('Firmware', 'Firmware'), help: t('60 to 10080 (1 week), default 720', '60 bis 10080 (1 Woche), Standard 720'), xs: 12, sm: 6, md: 3 },
        [k('t')]: txt('Values outside the range are corrected automatically.', 'Werte außerhalb des Bereichs werden automatisch angepasst.', small),
        [k('h')]: hdr('Logins', 'Anmeldungen'),
        attackThreshold: { type: 'number', min: 1, max: 100, label: t('Failed logins per address before alarm', 'Fehlversuche je Adresse bis Alarm'), xs: 12, sm: 6, md: 4, newLine: true },
        alertRemoteLogins: { type: 'checkbox', label: t('Report successful logins from the internet', 'Erfolgreiche Anmeldungen aus dem Internet melden'), xs: 12, sm: 6, md: 4 },
        knownIps: { type: 'text', label: t('Known addresses (comma separated, CIDR allowed)', 'Bekannte Adressen (Komma-getrennt, CIDR erlaubt)'), help: t('Logins from these addresses are not reported', 'Anmeldungen von hier werden nicht gemeldet'), xs: 12, md: 8, newLine: true },
        [k('h')]: hdr('New devices', 'Neue Geräte'),
        alertNewDevices: { type: 'checkbox', label: t('Report new devices in the network', 'Neue Geräte im Netz melden'), xs: 12, newLine: true },
        _randomWarn: { ...txt('Caution: many phones, tablets and laptops use private, changing addresses. After a change they look like a new device to the box. Mainly iPhone, iPad, Apple Watch and Mac ("Private Wi-Fi address"), Android 10 and later ("Randomized MAC"), Windows 10/11 ("Random hardware addresses") and Chromebooks.',
            'Achtung: Viele Handys, Tablets und Laptops nutzen private, wechselnde Adressen. Nach einem Wechsel hält die Box sie für ein neues Gerät. Betrifft vor allem iPhone, iPad, Apple Watch und Mac ("Private WLAN-Adresse"), Android ab 10 ("Zufällige MAC"), Windows 10/11 ("Zufällige Hardwareadressen") und Chromebooks.'), hidden: '!data.alertNewDevices', style: { color: 'orange' } },
        skipKnownPrivate: { type: 'checkbox', label: t('Do not report known devices that only got a new private address', 'Bekannte Geräte mit neuer privater Adresse nicht melden'),
            help: t('Recognised by the device name. A stranger could use the same name, so this is a trade-off.', 'Erkannt am Gerätenamen. Ein Fremder könnte denselben Namen nutzen, also ein Kompromiss.'), hidden: '!data.alertNewDevices', xs: 12, newLine: true },
        _devices: { type: 'textSendTo', command: 'devicesInfo', container: 'html', hidden: '!data.alertNewDevices', xs: 12, newLine: true },
        [k('h')]: hdr('Ports', 'Ports'),
        portSelfTest: { type: 'checkbox', label: t('Test open ports on the own WAN address', 'Offene Ports an der eigenen WAN-Adresse testen'), help: t('Only your own address. Tested from inside, so the result is limited.', 'Nur die eigene Adresse. Test von innen, Ergebnis eingeschränkt.'), xs: 12, newLine: true },
        [k('h')]: hdr('External services (privacy)', 'Externe Dienste (Datenschutz)'),
        vendorFirmwareCheck: { type: 'checkbox', label: t('Compare firmware with the vendor download server', 'Firmware mit dem Download-Server des Herstellers abgleichen'), xs: 12, newLine: true },
        [k('t')]: txt('Sends only the model name to download.avm.de. Off by default.', 'Überträgt nur den Modellnamen an download.avm.de. Standardmäßig aus.', small),
    } },
    findings: { type: 'panel', label: t('5. Findings', '5. Funde'), items: {
        [k('h')]: hdr('Current findings', 'Aktuelle Funde'),
        [k('t')]: txt('Shown when the settings are opened. The adapter must be running.', 'Wird beim Öffnen der Einstellungen geladen. Der Adapter muss laufen.', small),
        _findings: { type: 'textSendTo', command: 'findingsText', container: 'html', jsonData: '{"confirmations": ${JSON.stringify(data.confirmations)}}', alsoDependsOn: ['confirmations'], xs: 12, newLine: true },
        [k('h')]: hdr('Confirm as intended', 'Als gewollt bestätigen'),
        [k('t')]: txt('Some findings can be intended, e.g. a port forwarding you set up yourself. Confirmed findings are no longer reported and move to the end of the list above. If something changes about them, you get notified again.',
            'Manche Funde können gewollt sein, z. B. eine selbst eingerichtete Portfreigabe. Bestätigte Funde werden nicht mehr gemeldet und rutschen in der Liste oben nach unten. Ändert sich daran etwas, meldet sich der Adapter wieder.'),
        [k('t')]: txt('1. Click "Fetch findings into the table". 2. Tick what is intended. 3. Click "Save" at the bottom. Only then the confirmation counts.',
            '1. Auf "Funde in die Tabelle holen" klicken. 2. Bei Gewolltem den Haken setzen. 3. Unten auf "Speichern" klicken. Erst dann gilt die Bestätigung.', { style: { fontWeight: 'bold' } }),
        _loadConf: { ...send('loadConfirmations', t('Fetch findings into the table', 'Funde in die Tabelle holen'), []), useNative: true, variant: 'outlined' },
        confirmations: { type: 'table', noDelete: true, xs: 12, newLine: true, items: [
            { type: 'text', attr: 'title', title: t('Finding', 'Fund'), readOnly: true, noTranslation: true },
            { type: 'checkbox', attr: 'ok', title: t('Intended', 'Gewollt'), width: '6em' },
        ] },
        _sendSummary: { ...send('sendSummary', t('Send overview to Telegram / e-mail', 'Übersicht an Telegram / E-Mail schicken'), ['confirmations']), variant: 'outlined' },
        [k('t')]: txt('For scripts and VIS the same data is in the states of this instance, e.g. "summary.score" and "summary.text". Every state has a description.',
            'Für Skripte und VIS stehen dieselben Daten in den Datenpunkten dieser Instanz, z. B. "summary.score" und "summary.text". Jeder Datenpunkt hat eine Beschreibung.', small),
    } },
    diag: { type: 'panel', label: t('Diagnostics', 'Diagnose'), items: {
        [k('t')]: txt('Reads all relevant values once and stores them in "info.diagnostics". Passwords, keys, user names, addresses and serial numbers are masked as far as possible. Useful for bug reports, but read it before you share it. The result is shown below the button.',
            'Liest alle relevanten Werte einmal aus und legt sie in "info.diagnostics" ab. Kennwörter, Schlüssel, Benutzernamen, Adressen und Seriennummern werden so weit wie möglich geschwärzt. Hilfreich für Fehlermeldungen, vor dem Teilen aber selbst durchlesen. Das Ergebnis erscheint unter dem Knopf.'),
        _diagnose: { ...send('diagnose', t('Run diagnostics', 'Diagnose starten'), []), useNative: true },
        _diagView: { type: 'textSendTo', command: 'diagnosticsText', container: 'html', alsoDependsOn: ['_diagStamp'], xs: 12, newLine: true },
    } },
};

// The repochecker wants all five sizes on every item. Fill the missing ones from the next smaller size.
const NO_SIZE = ['header', 'divider', 'staticImage', 'infoBox', 'custom', 'panel', 'tabs'];
const SIZES = ['xs', 'sm', 'md', 'lg', 'xl'];
const sizes = items => {
    for (const item of Object.values(items)) {
        if (!NO_SIZE.includes(item.type)) {
            SIZES.forEach((s, i) => (item[s] ??= i ? item[SIZES[i - 1]] : 12));
        }
        if (item.items && !Array.isArray(item.items)) {
            sizes(item.items);
        }
    }
};
sizes(tabs);

fs.writeFileSync(path.join(dir, 'admin/jsonConfig.json'), JSON.stringify({ i18n: true, type: 'tabs', items: tabs }, null, 4) + '\n');
const en = {}, de = {};
for (const [e, d] of T) { en[e] = e; de[e] = d; }
// en and de come from here. The other languages are filled by "npm run translate", which only
// translates missing keys: keep what is there, drop keys that are gone, never write English.
const i18n = path.join(dir, 'admin/i18n');
for (const f of fs.readdirSync(i18n)) {
    const file = path.join(i18n, f);
    let data = f === 'en.json' ? en : f === 'de.json' ? de : undefined;
    if (!data) {
        const old = JSON.parse(fs.readFileSync(file, 'utf8'));
        data = Object.fromEntries(Object.keys(en).filter(key => old[key] !== undefined).map(key => [key, old[key]]));
    }
    fs.writeFileSync(file, JSON.stringify(data, null, 4) + '\n');
}
console.log(T.length, 'strings');
