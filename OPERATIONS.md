# Betrieb, Sicherung und Webhooks

## Sicherung

Eigentümer öffnen **Systemstatus → Sicherung herunterladen**, vergeben eine
mindestens zwölf Zeichen lange Passphrase und speichern die Datei mit der
Endung `.pkwsbackup` außerhalb des Camera-Hub-Hosts. Die Passphrase wird weder
in der Datenbank noch im Browser gespeichert.

Das Archiv enthält die konsistent über die SQLite-Backup-API gelesene
Anwendungsdatenbank und die für eine portable Neuverschlüsselung erforderliche
Quellschlüsselinformation ausschließlich innerhalb der AES-256-GCM-geschützten
Nutzlast. Sitzungen, OAuth-Einmalzustände, Videodaten, Protokolle und
CZEview-Sitzungscaches werden entfernt.

## Wiederherstellung

Unter **Systemstatus → Sicherung wiederherstellen** wird das Archiv zunächst
entschlüsselt und geprüft. Camera Hub kontrolliert Format, Version, Prüfsumme,
SQLite-Integrität, den vollständigen Migrationssatz, erforderliche Tabellen und
Spalten sowie alle Fremdschlüssel. Erst nach einer zweiten ausdrücklichen
Bestätigung wird übernommen.

Unmittelbar davor entsteht im persistenten Datenvolume unter
`restore-points/` eine lokale Rückfallsicherung. Die letzten drei
Rückfallpunkte bleiben erhalten. Geheimnisse werden mit dem Schlüssel der
Zielinstallation neu verschlüsselt; anschließend werden sämtliche
Anmeldesitzungen beendet.

## Ereignisse

Dauerstreams werden alle 30 Sekunden passiv über den MediaMTX-Status geprüft.
Eine Störung wird nach fünf Minuten ununterbrochenem Fehler geöffnet.
Gleichartige Beobachtungen bleiben ein Ereignis. Bei Erholung wird dieses
Ereignis genau einmal als behoben markiert.

On-Demand- und Akku-Kameras werden nicht periodisch kontaktiert oder geweckt.
Nur ein fehlgeschlagener Streamversuch aus einer aktiven Benutzeransicht
beginnt die Störungsbewertung. Snapshot-Kameras bleiben ohne aktiven
Frame-Test im Zustand „Status unbekannt“.

## Webhook-Signatur

Camera Hub sendet JSON per `POST` und setzt:

- `X-CameraHub-Event`: stabile Ereignis-ID;
- `X-CameraHub-Timestamp`: Unix-Zeitstempel der Zustellung;
- `X-CameraHub-Signature`: `sha256=<hex>` über
  `<Zeitstempel>.<unveränderte JSON-Bytes>`.

Der Empfänger berechnet HMAC-SHA-256 mit dem bei Anlage oder Rotation einmalig
angezeigten Geheimnis und vergleicht die Signatur konstantzeitlich. Zusätzlich
sollte er veraltete Zeitstempel und bereits verarbeitete Ereignis-IDs
zurückweisen.

Camera Hub folgt keinen Weiterleitungen und wartet höchstens fünf Sekunden.
Nach einer fehlgeschlagenen Erstzustellung folgen Versuche nach 1, 5, 15 und
60 Minuten. Danach bleibt die Zustellung als fehlgeschlagen dokumentiert.

## Anzeigegeräte

Unter **Systemstatus → Anzeigegeräte** legt der Eigentümer ein Gerät an, weist
Anzeigeprofile in Prioritätsreihenfolge zu und erzeugt einen Kopplungscode.
Auf dem Tablet oder Fernseher wird anschließend
`http://<camera-hub>/display.html` geöffnet. Der Code ist achtstellig, zehn
Minuten gültig und nur einmal verwendbar.

Das Gerät erhält eine widerrufbare HttpOnly-/SameSite-Strict-Sitzung. Sie
besitzt ausschließlich Leserechte auf das aktuell aktive, zugewiesene Profil,
dessen Kameradaten und genau die dazugehörigen geschützten Medienpfade. Die
Schaltfläche **Anzeige starten** fordert Browser-Vollbild an. Browser- oder
PWA-Kioskmodus können ergänzend verwendet werden.

Wochenzeitfenster werden in `CAMERA_HUB_TIMEZONE` (Standard:
`Europe/Berlin`) ausgewertet. Bei Überschneidungen gewinnt das in der
Gerätezuordnung höher angeordnete Profil. Ohne aktives Zeitfenster bleibt das
Gerät im Ruhebildschirm und lädt weder Kameraliste noch Medien.

Qualitätsmodi:

- `auto`: kompatibler Standardpfad mit HLS-Fallback;
- `high`: Hauptstream über WebRTC, ersatzweise derselbe Hauptpfad über HLS;
- `low`: ausschließlich der Substream über WebRTC;
- `hls`: Haupt- beziehungsweise vorhandener Einzelpfad über HLS.

Gerätesitzungen und Kopplungscodes sind nicht Bestandteil einer Sicherung.
Nach jeder Wiederherstellung müssen Anzeigen neu gekoppelt werden.

## Betriebsabnahme

Die automatischen Browser-, Medien-, Migrations- und
Wiederherstellungsprüfungen laufen in CI. Für die praktische 24-Stunden- und
48-Stunden-Freigabe gelten die Abläufe in
[poc/acceptance/README.md](poc/acceptance/README.md). Das passive
Dauerskript ruft keine Lease-, Wake-, Snapshot- oder Stream-Endpunkte auf.
