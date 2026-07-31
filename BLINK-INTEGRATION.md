# Blink-Integration

## Belastbarer Integrationsweg

Die im autorisierten LAN gefundenen Blink-Kameras und das Sync Module stellen
keinen belastbaren lokalen RTSP-, ONVIF- oder HTTP-Mediendienst bereit. Camera
Hub integriert sie deshalb über das Blink-Konto und den isolierten
`blink-bridge`-Container. Die Implementierung verwendet die in Camera Hub
gepflegte Kontoverwaltung; Klartext-Zugangsdaten oder erneuerte Token werden
nicht in Dateien, Logs oder im Browser abgelegt.

`blinkpy` ist eine inoffizielle, nicht von Blink/Amazon unterstützte Bibliothek.
Die Integration ist daher als bedarfsgesteuerter Cloud-Adapter gekennzeichnet
und kann durch Änderungen der Hersteller-API beeinträchtigt werden. Camera Hub
umgeht weder Zertifikatsprüfung noch Pinning. Die von `blinkpy 0.25.9` im
experimentellen IMMIS-Livepfad deaktivierte TLS-Prüfung wird im Adapter
ausdrücklich durch die normale System-Zertifikatsprüfung ersetzt.

## Konto und Suche

1. Als Eigentümer **Kameras suchen → Cloud-Konten → Blink-Konto** öffnen.
2. Bezeichnung, Blink-E-Mail-Adresse und Passwort eingeben.
3. Den von Blink gesendeten Bestätigungscode im zweiten Dialog eingeben.
4. **Nach Kameras suchen** starten.
5. Eine Kamera anhand ihres vorhandenen Cloud-Vorschaubilds hinzufügen.

Mehrere Blink-Konten werden getrennt gespeichert und bei jeder Suche
berücksichtigt. Eine erneute Anmeldung erhöht die Authentifizierungsrevision,
behält aber vorhandene Kamera-Zuordnungen bei.

## Akku- und Datenschutzgrenzen

- Metadaten werden höchstens einmal pro Minute aktualisiert.
- Der passive Aktualisierungspfad lädt keine Bild- oder Videodaten und fordert
  keine lokalen Sync-Module-Uploads an.
- Vorschaubilder sind vorhandene Cloud-Thumbnails; Camera Hub löst dafür kein
  neues Foto aus und hält sie 60 Sekunden im Arbeitsspeicher.
- Übersicht, Leitstellenmodus, Profile und Nur-Lese-Displays erzeugen keine
  Live-Leases.
- Live startet nur über **Blink-Livebild starten** in der Detailansicht.
- Eine Sitzung endet beim Verlassen, bei Lease-Verlust oder spätestens nach
  300 Sekunden. Pro Konto ist höchstens eine Live-Sitzung aktiv.
- Der Stream wird nur containerintern über FFmpeg an einen eigenen
  MediaMTX-Publisherpfad weitergegeben.
- Clips werden erst beim Öffnen oder Aktualisieren der Clipliste geladen,
  serverseitig auf 128 MB begrenzt und mit `no-store` ausgeliefert.

## Docker und Geheimnisse

Der Start erzeugt `poc/runtime/secrets/blink_adapter_token`. Dieses ignorierte
32-Byte-Geheimnis authentifiziert ausschließlich die interne Verbindung
zwischen Backend und Blink-Bridge. Der Container:

- veröffentlicht keinen Host-Port;
- läuft als UID/GID 10001 ohne Linux-Capabilities;
- besitzt ein schreibgeschütztes Root-Dateisystem und `no-new-privileges`;
- hat nur temporäre, größenbegrenzte Laufzeitverzeichnisse;
- ist auf 2 CPUs, 768 MB RAM und 128 Prozesse begrenzt;
- teilt nur das eigene Egress-Netz mit Backend und MediaMTX.

Konten, Gerätezuordnungen und verschlüsselte Authentifizierungsdaten sind Teil
der portablen Sicherung. Laufende Live-Sitzungen und Vorschaubild-Caches sind
reiner Laufzeitzustand und werden nach einer Wiederherstellung neu aufgebaut.

## Rückfall

Ein Blink-Konto kann deaktiviert werden, ohne die Kamera-Zuordnung zu löschen.
Der Container kann außerdem mit
`docker compose -f poc/docker-compose.yml stop blink-bridge` gestoppt werden.
Alle lokalen Kameraarten, Netatmo, CZEview, Erkennung und Benutzerfunktionen
bleiben unabhängig davon verfügbar. Ohne Bridge werden Blink-Vorschau, Clips
und Live verständlich als nicht verfügbar gemeldet.
