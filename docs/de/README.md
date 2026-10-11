![Logo](../../admin/fb-guard.png)
# ioBroker.fb-guard

Überwacht die Sicherheit deiner [FRITZ!Box](https://fritz.com) und meldet sich per Telegram oder E-Mail, wenn etwas auffällt.

## Was geprüft wird

- **Fehlgeschlagene Anmeldungen** aus dem Ereignisprotokoll, je Adresse zusammengefasst, mit Zeit, Benutzername, Zugangsweg und der Angabe, ob sie aus dem Internet oder aus dem Heimnetz kamen
- **Anmeldungen aus dem Internet** von Adressen, die nicht auf deiner Liste bekannter Adressen stehen
- **Offene Ports**: Portfreigaben, MyFRITZ!, Fernzugang, FTP über das Internet, TR-069 und UPnP, jeweils mit einer kurzen Erklärung, wofür der Port meist da ist
- **Firmware**: Update verfügbar, aber nicht installiert, automatische Updates aus
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
- Die Verbindung zur Box läuft über TLS. Das Zertifikat der Box wird beim ersten Verbinden gemerkt. Ändert es sich, meldet sich der Adapter nicht mehr an.
- Nach einer abgelehnten Anmeldung hört der Adapter auf, es weiter zu versuchen, damit er dich nicht aussperrt.
- Externe Dienste sind ab Werk aus. Derzeit gibt es nur einen: den Firmware-Abgleich mit dem Download-Server des Herstellers, der nur den Modellnamen überträgt.
- Der Port-Test prüft nur deine eigene WAN-Adresse.
- Die Diagnose schwärzt Kennwörter, Schlüssel, Benutzernamen, Adressen und Seriennummern.
- Tipp: Öffne den ioBroker-Admin über HTTPS, dann sind deine Eingaben auch auf dem Weg verschlüsselt.

Keine Garantie: Der Adapter hilft, Probleme zu bemerken, macht dein Netz aber nicht von allein sicher.

## Haftungsausschluss

FRITZ! und FRITZ!Box sind Marken der FRITZ! GmbH. Dieses Projekt steht in keiner Verbindung zur FRITZ! GmbH (ehemals AVM) und wird von ihr weder unterstützt noch geprüft. Keine Garantie für Sicherheit, Nutzung auf eigenes Risiko.
