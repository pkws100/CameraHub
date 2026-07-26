# Camera Hub 1.2.0

Camera Hub 1.2.0 erweitert das selbst gehostete, herstellerneutrale
Kamera-Gateway um persönliche Anzeigeprofile und die bisher vorbereiteten
Cloud-Adapter.

## Höhepunkte

- bis zu 32 über offene Standards verwaltbare Kameras;
- persönliche, benutzerisolierte Anzeigeprofile mit eigener Kamerareihenfolge;
- Profilwahl in Liveübersicht und Leitstellenmodus sowie geschützte Startlinks
  für Tablets und Fernseher;
- globale Kamera-Deaktivierung ohne Verlust von Verwaltung oder
  Profilzuordnung;
- WebRTC-Liveansicht mit HLS-Fallback;
- verschlüsselte Kamera-Zugangsdaten und rollenbasierte App-Anmeldung;
- ONVIF-Suche, Vorschau, Profile, Fähigkeiten und kontrollierte PTZ-Nutzung;
- mobile PWA, iOS-Lifecycle-Behandlung und Leitstellenmodus;
- mehrere CZEview- und Netatmo-Konten mit bedarfsgesteuerten Cloud-Streams;
- lokale HTTPS- und private LAN-/VPN-Bereitstellung ohne öffentliche
  Kameraports.

## Wichtige Hinweise

- Camera Hub verändert keine Kamera- oder Recorder-Einstellungen.
- Eine öffentliche Bereitstellung erfordert eine eigene abgesicherte
  WireGuard-/HTTPS-Architektur.
- Kamera-Zugangsdaten gehören niemals in `.env.example`, Compose-Dateien oder
  Git. Sie werden über die App verschlüsselt gespeichert.
- Der erste Eigentümer wird ausschließlich über Loopback eingerichtet.
- H.265- und MJPEG-Transcoding kann je nach Kamera erhebliche CPU-Ressourcen
  benötigen.

Installations- und Sicherheitshinweise stehen in
[README.md](README.md) und [SECURITY.md](SECURITY.md).
