# Änderungsprotokoll

Alle wesentlichen Änderungen an Camera Hub werden in dieser Datei dokumentiert.

## [Unveröffentlicht – 1.4.0]

### Hinzugefügt

- widerrufbare Nur-Lese-Anzeigegeräte mit achtstelligem, zehn Minuten gültigem
  Einmalcode und 180-Tage-Gerätesitzung;
- priorisierte Profilzuordnung, wiederkehrende Wochenzeitpläne in einer
  konfigurierbaren Zeitzone und privater Ruhebildschirm ohne Kameraabrufe;
- Qualitätsmodus `auto`, `high`, `low` oder `hls` pro Kamera und Anzeigeprofil;
- additive Datenbankmigration für Geräte, Sitzungen, Codes, Zuordnungen,
  Zeitpläne und Qualitätsmodus;
- Browserabnahme auf Desktop, Tablet und Mobilgerät sowie ein echter
  Caddy-/MediaMTX-/H.264-Teststapel mit elf Quellen.

### Sicherheit

- Kopplungscodes und Gerätetokens werden nur gehasht gespeichert und
  Fehlversuche je Quelladresse und Code begrenzt;
- Gerätesitzungen können weder Verwaltung noch PTZ, Cloud-Konten, Backups oder
  Ereignisdetails öffnen und sind auf aktive, zugewiesene Medienpfade begrenzt;
- Sicherungen erhalten die Gerätekonfiguration, entfernen aber alle
  Gerätesitzungen und Kopplungscodes.

## [1.3.3 – Freigabe ausstehend]

### Hinzugefügt

- reproduzierbare synthetische H.264-, MediaMTX-, Caddy-, WHEP- und HLS-Abnahme;
- verbindliche CZEview-Brückentests und Browserregression in GitHub Actions;
- ausschließlich passive, bereinigte 24-Stunden-Dauerabnahme ohne Wake- oder
  Lease-Aufrufe für Akku- und Cloudkameras.

### Freigabe

- Der Tag `v1.3.3` bleibt bis zum bestandenen 24-Stunden-Lauf und der
  praktischen Wiederherstellung gesperrt.

## [1.3.2] – 2026-07-26

### Behoben

- Technisch geprüfte Netatmo- und CZEview-Kameras werden über einen regulären,
  barrierearmen Dialog benannt und importiert; der nicht überall unterstützte
  Browser-Prompt entfällt.
- Läuft die Sicherheitsfreigabe während Import oder Streamprüfung ab, bleibt
  der Arbeitsstand erhalten und die Passwortbestätigung wird eindeutig
  vorgeschaltet.

## [1.3.1] – 2026-07-26

### Verbessert

- Ereignisse zeigen ihre berechnete Dauer ausdrücklich an.
- Cloud-Kameras unterscheiden eine erforderliche Neuanmeldung nun auch im
  Kamera- und Verbindungsstatus.

## [1.3.0] – 2026-07-26

### Hinzugefügt

- portable, mit einer Betreiber-Passphrase verschlüsselte Sicherungen für
  Benutzer, Kameras, Verbindungen, Cloud-Konten, Profile, Zonen und
  Betriebseinstellungen;
- vollständige Archivprüfung, Neuverschlüsselung für die Zielinstallation,
  lokaler Rückfallpunkt und Sitzungswiderruf bei der Wiederherstellung;
- dauerhafte, deduplizierte Betriebsereignisse mit fünfminütiger
  Störungsschwelle, Entwarnung und verständlichen Handlungsempfehlungen;
- passive Überwachung lokaler Dauerstreams und Cloud-Kontozustände, ohne
  Akku- oder On-Demand-Kameras periodisch zu wecken;
- HMAC-SHA-256-signierte Webhooks mit Ereignisfilter, Testnachricht,
  Geheimnisrotation und Wiederholungen nach 1, 5, 15 und 60 Minuten;
- Eigentümeroberfläche für Sicherungen und Webhooks sowie eine rollenlesbare
  Ereignisübersicht auf der Systemseite.

### Sicherheit

- Sicherungsarchive verwenden Scrypt und AES-256-GCM, enthalten keine
  Laufzeitsitzungen und werden vor jeder Übernahme vollständig validiert;
- Webhook-Nutzdaten enthalten weder Passwörter, Zugriffstoken, Stream-Adressen
  noch interne Servicetoken und folgen keinen HTTP-Weiterleitungen.

## [1.2.0] – 2026-07-26

### Hinzugefügt

- persönliche Anzeigeprofile je Benutzer mit eigener Kameraauswahl und
  Kachelreihenfolge für Live- und Leitstellenansicht;
- geschützte Startlinks für Tablets und Fernseher, die nach der normalen
  Anmeldung direkt ein persönliches Profil öffnen;
- Profilauswahl in der Liveübersicht und in den einblendbaren
  Leitstellen-Steuerelementen;
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

- die vorhandene Kamera-Deaktivierung wirkt als globale Sperre für sämtliche
  Anzeigeprofile, ohne deren Zuordnung oder Reihenfolge zu löschen;
- Profilwechsel schließen nicht mehr benötigte Streams und geben deren
  Kamera-Leases frei;
- CZEview-Kontoprozesse reagieren nur noch auf eine eigene
  Zugangsdatenrevision statt auf den bei jeder Inventur geänderten allgemeinen
  Kontozeitstempel;
- vorhandene CZEview-Sitzungscaches werden bei der einmaligen Übernahme aus
  `poc/.env` weiterverwendet;
- ein einzelner vorübergehender CZEview-API-Fehler löscht den Sitzungscache
  nicht mehr. Eine kontrollierte Neuanmeldung erfolgt erst nach drei
  aufeinanderfolgenden Kontofehlern und höchstens einmal je 30 Minuten;
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

[1.3.2]: https://github.com/pkws100/CameraHub/releases/tag/v1.3.2
[1.3.1]: https://github.com/pkws100/CameraHub/releases/tag/v1.3.1
[1.3.0]: https://github.com/pkws100/CameraHub/releases/tag/v1.3.0
[1.2.0]: https://github.com/pkws100/CameraHub/releases/tag/v1.2.0
[1.0.0]: https://github.com/pkws100/CameraHub/releases/tag/v1.0.0
