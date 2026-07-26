# Sicherheitsgrenzen

## Geräte und Netzwerk

- Keine Konfigurationsänderungen an Kameras oder Receiver.
- Kein Login auf TCP 23, keine Firmware-, Reset-, Passwort-, Netzwerk-,
  Aufnahme- oder Speicheraktionen.
- Keine proprietären Binärpakete, Exploit-, Fuzzing- oder Brute-Force-Tests.
- Discovery bleibt auf das ausdrücklich konfigurierte private IPv4-Netz,
  feste Ports, begrenzte Parallelität, einen Scan gleichzeitig und mindestens
  60 Sekunden Abstand beschränkt.
- Zulässig sind WS-Discovery, lesende ONVIF-Abfragen, TCP-Connect, RTSP
  OPTIONS/DESCRIBE und ein zeitlich begrenzter Frame-Test.
- Ein Discovery-Treffer verändert weder Gerät noch lokale Kameraliste.

## Anmeldung und Secrets

- Liveansicht und Verwaltung erfordern eine Eigentümersitzung.
- Passwörter werden mit Argon2 gehasht; Kamera-Zugangsdaten mit AES-GCM
  verschlüsselt.
- Sitzungscookie: HttpOnly, SameSite Strict und unter HTTPS zusätzlich Secure.
- Rollen werden an jedem geschützten API-Endpunkt serverseitig geprüft.
- Nur Eigentümer verwalten Benutzer; Administratoren verwalten Kameras und Zonen;
  Betrachter erhalten ausschließlich lesenden Livezugriff.
- Das letzte aktive Eigentümerkonto und das eigene aktive Konto sind gegen
  versehentliche Sperrung oder Löschung geschützt.
- Passwortzurücksetzung, Deaktivierung und Rollenwechsel widerrufen betroffene
  Sitzungen.
- Schreibende APIs verlangen CSRF-Token; Verwaltungsänderungen außerdem eine
  höchstens zehn Minuten alte Passwortbestätigung.
- Fünf falsche Anmeldungen pro Konto und vertrauenswürdig ermittelter
  Quelladresse führen zu einer zeitweisen Sperre. Die erneute
  Passwortbestätigung besitzt ein eigenes Limit.
- Bootstrapcode, Schlüssel, Datenbank, Testbilder und Runtime-Konfiguration
  liegen ausschließlich in ignorierten lokalen Verzeichnissen.
- Browser-API, Web Storage und normale Logs enthalten keine Kamera-Secrets oder
  authentifizierten Quell-URIs.
- Kamera-Verbindungen werden revisionsweise gespeichert. Benutzer- und
  Passwortfelder bleiben beim Bearbeiten leer; APIs liefern nur
  Vorhanden-/Nicht-vorhanden-Markierungen.
- Die optionale CZEview-Brücke erhält nur die ausdrücklich ausgewählten
  CZEview-Felder als Docker-Secret. `.env`, Plattform-Token, Seriennummer und
  Kontodaten werden nicht über Viewer- oder Verwaltungs-APIs ausgeliefert.
- Wegen der Plattformgrenze wird für CZEview ein eigenes, freigegebenes
  Betrachterkonto empfohlen. Ein gemeinsam mit der Mobil-App verwendetes Konto
  kann dort durch die Brückenanmeldung abgemeldet werden.
- ONVIF unterstützt HTTP Basic/Digest und WS-Security PasswordDigest. Das
  Klartextpasswort wird nicht in den SOAP-Header übernommen.
- PTZ-Bewegung und vorhandene Presets sind nur für Eigentümer/Administratoren,
  mit CSRF-Schutz, Rate-Limit und aktueller Passwortbestätigung freigeschaltet.
  Ein Stop-Befehl wird auch bei Abbruch, Hintergrundwechsel und Seitenwechsel
  gesendet.
- Die CZEview-Brücke veröffentlicht ihren Steueradapter nicht auf dem Host.
  Camera Hub darf ihn nur über den fest erlaubten internen Dienstnamen und das
  Service-Token ansprechen. Freigegeben sind ausschließlich begrenzte
  Links-/Rechtsbewegungen und Stopp; vertikale Bewegung, Zoom, Kalibrierung
  und Presets bleiben für diese Kamera deaktiviert.
- ONVIF- und Snapshot-HTTP-Clients folgen keinen Weiterleitungen. Ein geprüftes
  Kameraziel kann dadurch nicht auf Link-Local-, Internet- oder interne
  Containeradressen umleiten.
- ONVIF-Fähigkeiten und PTZ-Profile müssen exakt zur aktiven
  Verbindungsrevision gehören. Ein Revisionswechsel invalidiert alte Tokens.
- Portable Sicherungen sind außen mit einer per Scrypt (`N=2^17`, `r=8`,
  `p=1`) abgeleiteten
  AES-256-GCM-Schlüsselung geschützt. Die Passphrase wird nicht gespeichert.
  Laufzeitsitzungen und OAuth-Einmalzustände werden nicht exportiert.
- Eine Wiederherstellung verlangt Eigentümerrolle, CSRF-Schutz und aktuelle
  Passwortbestätigung. Archiv, Prüfsumme, SQLite-Integrität und Schemaversion
  werden vor jeder Änderung geprüft; Geheimnisse werden mit dem Schlüssel der
  Zielinstallation neu verschlüsselt.
- Webhooks akzeptieren ausschließlich HTTP-/HTTPS-Ziele, folgen keinen
  Weiterleitungen und signieren Zeitstempel und unveränderte JSON-Nutzlast mit
  HMAC-SHA-256. Private LAN-Ziele sind für den lokalen Betrieb ausdrücklich
  zulässig. Webhook-Nutzdaten enthalten keine Zugangsdaten, Token oder
  Stream-URIs.

## Medien und Alarmvorbereitung

- MediaMTX-API, interner RTSP-Port, Relay-UDP-Ports, Datenbank und Detection-API
  werden nicht auf dem Host veröffentlicht.
- Der Relay-Manager besitzt keinen Docker-Socket. Temporäre Playlists mit
  Quell-Secrets liegen nur in einem Container-tmpfs.
- H.265/MJPEG-Transcoding wird nur bei aktivem Lease gestartet; H.264 bleibt
  Stream-Copy. Die CZEview-Ausnahme codiert kurze proprietäre H.264-P2P-Fenster
  bedarfsgesteuert mit häufigen Schlüsselbildern neu, damit später
  hinzukommende WebRTC-/HLS-Leser einsteigen können.
- Die CZEview-Kamera wird nur bei einem erneuerbaren Viewer-Lease geweckt. Das
  Schließen oder Pausieren der Ansicht gibt den Lease frei; die Brücke beendet
  anschließend ihren Publisher. Ein Snapshot verwendet einen eigenen
  kurzlebigen Lease und entfernt ihn auch bei Timeout oder Fehler.
- Vorschauen werden bevorzugt aus dem neutralen internen MediaMTX-Pfad
  erzeugt, nicht über eine zweite direkte Kamerasitzung. Gleichzeitige
  FFmpeg-Vorschauen sind begrenzt; Antworten werden nicht dauerhaft gespeichert
  und mit `no-store` geliefert.
- Detection-Konfiguration ist nur über internes Service-Token erreichbar; der
  Ereigniseingang antwortet in Version 1 mit „deaktiviert“.
- ONVIF Imaging, Geräte-I/O, Events und Analytics werden ausschließlich
  gelesen. Es existieren keine API-Endpunkte für Preset-Verwaltung,
  Imaging-Schreibzugriffe, Gegensprechen, Sirene, Licht oder Relais.
- Der Service Worker ignoriert API, WHEP, HLS, interne Endpunkte und Video.

## Veröffentlichung

- Standardbetrieb bleibt Loopback.
- LAN/VPN-Verwaltung ist nur über den gemeinsamen lokalen HTTPS-Origin erlaubt.
- Der private Hostmodus bindet ausschließlich an eine ausdrücklich angegebene
  RFC1918-Adresse. Die Firewall akzeptiert nur konkrete private Quellnetze und
  lehnt `Any`, öffentliche Netze und Standardrouten ab.
- Im privaten Hostmodus werden ausschließlich TCP 443 sowie der belegte
  WebRTC-Medienport 8189/TCP+UDP veröffentlicht. HLS, WHEP, API und PWA teilen
  sich den geschützten HTTPS-Origin; interne Ports bleiben unveröffentlicht.
- Im HTTPS-Modus werden auch die früheren Loopback-Debugports 8888/8889 nicht
  mehr auf dem Host veröffentlicht. Medienzugriff erfordert dadurch immer die
  App-Sitzung am Reverse-Proxy.
- Weiterleitungsheader werden nur vom festgelegten internen Docker-Proxynetz
  akzeptiert; Uvicorn wertet solche Header nicht eigenständig aus.
- Der private HTTP-Gateway-Modus ist eine ausdrückliche Ausnahme für
  vertrauenswürdige lokale Anzeige- und Verwaltungsgeräte. Er bindet an eine
  konkrete RFC1918-Adresse und leitet das zulässige Verwaltungsnetz aus deren
  aktiver Präfixlänge ab. Die Windows-Firewall begrenzt den Zugriff zusätzlich
  auf dasselbe konkrete Quellsubnetz. HLS und WHEP bleiben dabei hinter der
  App-Sitzung am lokalen Reverse Proxy; MediaMTX-Webports werden nicht direkt
  veröffentlicht.
- Für WireGuard/Nginx Proxy Manager bleibt äußeres HTTPS erforderlich.
  `X-Forwarded-Proto` wird nur von ausdrücklich vertrauten Proxy-Netzen
  akzeptiert. Der direkte private HTTP-Modus darf niemals öffentlich geroutet
  oder per Routerfreigabe erreichbar gemacht werden.
- Kamera-, Receiver-, RTSP-, Docker-, Verwaltungs- und Metrikports werden nie
  öffentlich freigegeben.
- Ein späterer VPS darf den Host nur über WireGuard erreichen. Die öffentliche
  Domain endet am Nginx Proxy Manager mit einem öffentlich vertrauenswürdigen
  Zertifikat. Das lokale CA-Zertifikat und insbesondere sein privater Schlüssel
  werden nicht auf dem VPS veröffentlicht.
- Keine Cloud, Werbung, Tracker, externen Schriften oder Analyseplattformen.
- Die alte Kameraauthentifizierung ist keine Sicherheitsgrenze; Zugang erfolgt
  nur über Netzisolation, VPN und das authentifizierte Gateway.
