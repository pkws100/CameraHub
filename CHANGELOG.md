# Änderungsprotokoll

Alle wesentlichen Änderungen an Camera Hub werden in dieser Datei dokumentiert.

## [Unveröffentlicht]

### Dokumentation

- CZEview-ZY-Q5-Akku-/Cloudkamera im Schlaf- und Wachzustand schonend
  untersucht;
- fehlenden lokalen Standardstream und die Grenze zu undokumentierten
  App-/Cloudsitzungen nachvollziehbar dokumentiert;
- Anforderungen für einen späteren offiziellen, lease-basierten
  Provider-Adapter festgelegt;
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
