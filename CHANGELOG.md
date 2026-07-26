# Änderungsprotokoll

Alle wesentlichen Änderungen an Camera Hub werden in dieser Datei dokumentiert.

## [Unveröffentlicht]

### Hinzugefügt

- vollständige Cloud-Konto-Verwaltung mit Umbenennen, Aktivieren, Deaktivieren,
  CZEview-Zugangserneuerung und Netatmo-Wiederverbindung ohne doppelte Konten;
- reproduzierbarer Abschlussbericht und Netatmo-Abnahmeablauf für die
  Mehrkonto-Suche;
- verschlüsselte Mehrkonto-Verwaltung für CZEview und Netatmo direkt in der
  Kamerasuche;
- zusammengeführte LAN-/Cloud-Suche mit konto- und herkunftsspezifischem Status;
- Netatmo-OAuth-Codefluss mit Einmalzustand, Token-Erneuerung und
  Frame-geprüftem On-Demand-Relay;
- getrennte interne Adapter-Tokens für CZEview und Netatmo;
- mehrere parallele CZEview-Konten mit getrennten Sitzungsspeichern und
  höchstens einem aktiven Akku-Kamerastream je Konto;
- optionale CZEview-P2P-Brücke für die untersuchte Akku-/Solarkamera;
- bedarfsgesteuertes Wake-on-View, erneuerbare Kamera-Leases und automatische
  Registrierung eines neutralen externen MediaMTX-Pfads;
- kurzlebiger Snapshot-Lease, der eine schlafende Akku-Kamera für genau eine
  JPEG-Erfassung weckt und danach wieder freigibt;
- H.264-Aufbereitung mit häufigen Schlüsselbildern für zuverlässigen
  WebRTC-, HLS- und Snapshot-Einstieg;
- rollen- und CSRF-geschützter horizontaler CZEview-Schwenk über einen
  internen, begrenzten Steueradapter;
- reproduzierbare CZEview-Evidenz- und Betriebsdokumentation;
- Erkennung des standardisierten Tapo-ONVIF-Dienstes auf Port 2020;
- Tapo-kompatible, weiterhin bearbeitbare Vorschläge für Haupt- und Substream;
- Übernahme des ONVIF-Endpunkts bereits bei der verschlüsselten
  Kamera-Ersteinrichtung;
- automatische lesende ONVIF-Funktionserkennung nach erfolgreichem
  RTSP-Frame-Nachweis;
- Erkennung von H.264-B-Frames in Haupt- und Substream sowie ein gezielter
  H.264-Baseline-Kompatibilitäts-Relay ausschließlich für betroffene Quellen;
  bestehende WebRTC-kompatible Quellen bleiben im Stream-Copy-Pfad;
- interner, nicht am Host veröffentlichter MediaMTX-RTSP-Eingang für Kameras,
  deren kurze RTSP-Sitzung ein standardisiertes Keepalive benötigt.

### Geändert

- RTSP-Frame-Tests erlauben langsamer startenden Kameras ein kontrolliertes
  Zeitfenster, ohne aggressive Wiederholungen.

### Sicherheit

- CZEview-Zugangsdaten werden aus der ignorierten `.env` in eine
  ACL-geschützte Runtime-Secret-Datei übertragen;
- Konto, Passwort, Plattform-Token, Geräte-ID und Seriennummer werden weder an
  Viewer-APIs noch an normale Logs ausgegeben;
- die Brücke besitzt keinen Docker-Socket und nutzt nur das interne
  Service-Token sowie interne MediaMTX-Endpunkte;
- der CZEview-Steueradapter wird nicht auf dem Host veröffentlicht und
  akzeptiert ausschließlich authentifizierte Links-/Rechts-/Stoppbefehle;
- der private HTTP-Modus leitet sein zulässiges Verwaltungsnetz aus dem aktiven
  lokalen Interface ab; der für CZEview erforderliche RTSP-Publisher bleibt
  ausschließlich im internen Docker-Netz erreichbar.

### Dokumentation

- CZEview-Akku-/Cloudkamera zunächst im Schlaf- und Wachzustand schonend auf
  lokale Standarddienste untersucht und den später nachgewiesenen
  kontogestützten P2P-Zugriff getrennt dokumentiert;
- Ignore-Regeln um Paket-, Browser- und lokale Providerartefakte ergänzt.

## [1.0.0] – 2026-07-24

### Hinzugefügt

- geschützte Multi-Kamera-PWA mit responsiver Übersicht, Einzelansicht und
  randlosem Leitstellenmodus;
- Eigentümer-, Administrator- und Betrachterrollen;
- verschlüsselte, versionierte Kamera-Verbindungen mit Prüfung, Aktivierung
  und Rollback;
- ONVIF-/WS-Discovery sowie manuelle RTSP-, HLS-, MJPEG- und
  Snapshot-Einrichtung;
- dynamischer Relay-Manager und MediaMTX-Ausgabe über WebRTC mit HLS-Fallback;
- Anzeige authentifizierter Kameraquellen ohne Preisgabe von Zugangsdaten;
- PTZ-Steuerung und vorhandene Presets für unterstützte ONVIF-Kameras;
- sortierbare Kameras, normalisierte Alarm-/Ausschlusszonen und deaktivierter
  Detection-Adaptervertrag;
- lokale HTTPS-, Firewall-, Status-, Start-, Stopp- und Rollbackwerkzeuge;
- automatisierte Integrations-, Syntax- und Compose-Prüfungen.

### Sicherheit

- Argon2-Passworthashes, AES-GCM-verschlüsselte Kamera-Zugänge,
  CSRF-Schutz, Sitzungswiderruf und Rate-Limits;
- keine Kamera-Secrets in Viewer-APIs, Browser-Speichern oder
  Service-Worker-Caches;
- standardmäßige Loopback-Bindung und eng begrenzbare private
  LAN-/VPN-Freigabe.

[1.0.0]: https://github.com/pkws100/CameraHub/releases/tag/v1.0.0
