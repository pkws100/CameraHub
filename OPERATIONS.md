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
