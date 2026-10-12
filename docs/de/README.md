![Logo](../../admin/fb-guard.png)
# ioBroker.fb-guard

Überwacht die Sicherheit deiner [FRITZ!Box](https://fritz.com) und meldet sich per Telegram oder E-Mail, wenn etwas auffällt.

## Wozu

Wer in die Oberfläche deiner Box kommt, hat das ganze Heimnetz in der Hand: Portfreigaben, DNS, Telefonie, VPN-Zugänge. Das kann über ein erratenes oder abgegriffenes Kennwort passieren, über eine Sicherheitslücke in der Firmware oder über eine Freigabe, die vor Jahren eingerichtet und vergessen wurde. Die Box schreibt das meiste davon ins Ereignisprotokoll, aber dort liest es niemand, und warnen tut sie nicht.

fb-guard liest es für dich. Gemeldet werden fehlgeschlagene und unerwartete Anmeldungen an der Box selbst (Oberfläche, Fernzugang, Apps, TR-064) und getrennt davon Geräte, die mit falschem Schlüssel ins WLAN wollen. Dazu prüft er die Einstellungen, die einen Angriff leichter machen.

## Was geprüft wird

- **Fehlgeschlagene Anmeldungen** aus dem Ereignisprotokoll, je Adresse zusammengefasst, mit Zeit, Benutzername, Zugangsweg und der Angabe, ob sie aus dem Internet oder aus dem Heimnetz kamen
- **Fehlgeschlagene WLAN-Anmeldungen** (falscher Schlüssel), je Gerät zusammengefasst, mit dem Hinweis, ob die Box das Gerät schon kennt
- **Anmeldungen aus dem Internet** von Adressen, die nicht auf deiner Liste bekannter Adressen stehen
- **Offene Ports**: Portfreigaben, MyFRITZ!, Fernzugang, FTP über das Internet, TR-069 und UPnP, jeweils mit einer kurzen Erklärung, wofür der Port meist da ist
- **Firmware**: Update verfügbar, aber nicht installiert, automatische Updates aus, Labor-Firmware und neuere Labor-Versionen, und ob dein Modell überhaupt noch Updates bekommt oder eine neue Box fällig ist
- **Einstellungen**: Werkskennwort aktiv, Anmeldung ohne Kennwort, Zwei-Faktor-Anmeldung aus, neue Box-Benutzer, offenes oder schwaches WLAN, WPS
- **Neustarts der Box** (dabei wird das Ereignisprotokoll geleert)
- Ein **Sicherheitswert von 0 bis 100** für deine Visualisierung

Der Adapter liest nur. Er ändert nichts an der Box und spricht nur mit deiner eigenen Box.

## Einrichtung

1. Adapter installieren und die Einstellungen öffnen. Die Reiter führen von links nach rechts durch die Einrichtung.
2. Auf der Box einen eigenen Benutzer für den Adapter anlegen, nur mit dem Recht "FRITZ!Box Einstellungen" und ohne Zugang aus dem Internet.
3. "Verbindung testen" klicken.
4. Telegram und/oder E-Mail wählen und eine Testnachricht senden.

Alle Funde stehen in den Einstellungen im Reiter "Funde", jeweils mit Erklärung. Was gewollt ist (z. B. eine selbst eingerichtete Portfreigabe), hakst du dort ab und speicherst. Danach wird es nicht mehr gemeldet. Ändert sich daran etwas, meldet sich der Adapter wieder. Auf Wunsch kommt täglich oder wöchentlich eine Übersicht aller offenen Funde.

## Sicherheit und Datenschutz

- Das Kennwort wird in ioBroker verschlüsselt gespeichert und nie ins Log geschrieben.
- Die Verbindung zur Box läuft über TLS. Der Schlüssel des Box-Zertifikats wird beim ersten Verbinden gemerkt. Ändert er sich, meldet sich der Adapter nicht mehr an. "Verbindung testen" zeigt den Fingerabdruck des Zertifikats, damit du ihn mit der Box vergleichen kannst.
- Nach einer abgelehnten Anmeldung hört der Adapter auf, es weiter zu versuchen, damit er dich nicht aussperrt.
- Externe Dienste sind ab Werk aus. Derzeit gibt es nur einen: den Firmware-Abgleich. Er liest die Versionsdatei vom Download-Server des Herstellers, die öffentliche Liste zur Produktunterstützung auf fritz.com und bei Labor-Firmware die öffentliche Labor-Seite. Übertragen wird höchstens der Modellname.
- Der Port-Test prüft nur deine eigene WAN-Adresse.
- Die Diagnose schwärzt Kennwörter, Schlüssel, Benutzernamen, Adressen und Seriennummern.
- Tipp: Öffne den ioBroker-Admin über HTTPS, dann sind deine Eingaben auch auf dem Weg verschlüsselt.

Keine Garantie: Der Adapter hilft, Probleme zu bemerken, macht dein Netz aber nicht von allein sicher.

## Haftungsausschluss

FRITZ!, FRITZ!Box, FRITZ!OS und MyFRITZ! sind Marken der FRITZ! GmbH. Dieses Projekt steht in keiner Verbindung zur FRITZ! GmbH (ehemals AVM) und wird von ihr weder unterstützt noch geprüft. Keine Garantie für Sicherheit, Nutzung auf eigenes Risiko.
