# Camera Hub – dauerhafte Codex-Projektregeln

## Auftrag und Prioritäten

Camera Hub ist ein lokales, herstellerneutrales Multi-Kamera-Gateway. Änderungen
müssen bestehende Zmodo-, ONVIF-, RTSP-, HLS-, MJPEG-, Snapshot-, MediaMTX-,
WebRTC-, Tapo-, CZEview-, Netatmo-, Blink-, Benutzer-, Rollen-, Lease-, Backup-,
Webhook-, Anzeigeprofil-, Display- und Alarmzonenfunktionen erhalten.

Prioritäten in dieser Reihenfolge:

1. Sicherheit, Datenschutz und Erhalt vorhandener Daten.
2. Keine unbeabsichtigten Wake-, Lease-, Snapshot- oder Live-Aufrufe bei Akku-
   und On-Demand-Kameras.
3. Regressionsfreiheit für alle bereits unterstützten Kameras.
4. Reproduzierbare Tests und nachvollziehbare technische Evidenz.
5. Verständliche Bedienung auf Desktop, Tablet, Mobilgerät und Leitstellenanzeige.

## Repository und Architektur

- GitHub: `pkws100/CameraHub`.
- Backend: FastAPI und SQLite in `poc/backend/`.
- Web-App/PWA: `poc/web/`.
- Medienserver: MediaMTX; Konfiguration in `poc/mediamtx*.yml`.
- Reverse Proxy: Caddy in `poc/proxy/`.
- Dynamische Relays: `poc/manager/`; Kompatibilitätsrelays: `poc/relay/`.
- Cloud-/Herstelleradapter: `poc/czeview/`, `poc/netatmo/`, `poc/blink/`.
- Lokale Alarmzonenerkennung: `poc/detection/`.
- Browser- und Streamabnahme: `poc/e2e/` und `poc/acceptance/`.
- Lokaler Docker-Start: `start-zmodo-pwa.ps1`; Status und Stopp über die
  entsprechenden Skripte im Repository-Root.

Die lokale HTTP-Bereitstellung im ausdrücklich autorisierten privaten Netz ist
ein unterstütztes Betriebsmodell. Keine allgemeine HTTPS-Pflicht neu einführen.

## Arbeitsweise

- Vor Änderungen `git status -sb`, aktuellen Branch, Remote und relevante
  Dokumentation prüfen.
- Existierende Benutzeränderungen nicht überschreiben oder zurücksetzen.
- Für neue Arbeit einen passenden Feature-Branch verwenden. `main` bleibt der
  stabile Integrationszweig.
- Additive, rückwärtskompatible Datenbankmigrationen verwenden. Migrationen
  müssen wiederholte Starts verkraften und vorhandene Fremdschlüssel erhalten.
- Bei Änderungen an Datenbank oder Restore immer zuerst eine SQLite-Backupkopie
  mit der SQLite-Backupfunktion prüfen; aktive DB-Dateien nie roh kopieren.
- Behauptungen zu OEM, Modellfamilie, Chipsatz oder Protokoll nur mit belastbarer
  technischer Evidenz dokumentieren.
- Externe Hersteller- oder Cloud-APIs als instabil behandeln. Fehler eines
  Adapters dürfen lokale Streams, Anmeldung oder Verwaltung nie blockieren.
- Nur ausdrücklich angeforderte externe Schreibaktionen ausführen. Commit,
  Push, PR, Merge, Release und Deployment sind getrennte Schritte.

## Akku-, Cloud- und Medienregeln

- CZEview, Blink, Netatmo und andere On-Demand-Kameras nie durch Übersicht,
  Leitstelle, Displays, Statusprüfungen, Zeitpläne oder Hintergrundüberwachung
  zyklisch wecken.
- Passive Metadaten, vorhandene Cloud-Thumbnails und bereits laufende
  MediaMTX-Streams bevorzugen.
- Livezugriff auf Akku-/Cloudkameras nur nach einer bewussten Benutzeraktion
  und mit einem begrenzten, widerrufbaren Lease.
- Keine Zugangsdaten, Tokens oder vollständigen Stream-URLs in Browserpayloads,
  Ereignisse, Webhooks, Logs oder Testberichte übernehmen.
- TLS-Zertifikatsprüfung und Hersteller-Sicherheitsmechanismen nicht abschalten
  oder umgehen.
- Ein Worker oder Adapter darf keine Host-Ports veröffentlichen, sofern dies
  nicht technisch erforderlich und ausdrücklich dokumentiert ist.
- Kamerabilder und Clips mit `no-store` ausliefern. Größen-, MIME- und
  Berechtigungsprüfungen serverseitig durchführen.

## Geheimnisse und lokale Daten

- Niemals `.env`, `poc/.env`, `poc/runtime/`, Datenbanken, Tokens, Schlüssel,
  Zertifikate, PCAPs, HARs oder reale Zugangsdaten committen.
- Geheimnisse ausschließlich aus ignorierten Dateien oder Docker-Secrets lesen.
- Neue Secrets zufällig erzeugen, getrennt je Dienst verwenden und nur minimal
  berechtigten Containern bereitstellen.
- Vor jedem Commit `git status --short --untracked-files=all` und
  `git diff --check` ausführen.

## Verifikation

Tests risikogerecht auswählen. Bei Änderungen an gemeinsamen Kamera-, Medien-,
Authentifizierungs-, Datenbank- oder UI-Pfaden ist die vollständige Regression
erforderlich.

Mindestens relevante Prüfungen:

```powershell
node --check poc/web/app.js
node --check poc/web/display-device.js
python -m py_compile poc/backend/app.py
docker build -t camerahub-backend-test poc/backend
docker run --rm --entrypoint python -e PYTHONPATH=/app camerahub-backend-test /app/tests/integration.py
docker build -t camerahub-czeview-test poc/czeview
docker run --rm --entrypoint python -e PYTHONPATH=/app camerahub-czeview-test -m unittest discover -s /app/tests -p 'test_*.py'
docker build -t camerahub-detection-test poc/detection
docker run --rm --entrypoint python -e PYTHONPATH=/app camerahub-detection-test -m unittest discover -s /app/tests -p 'test_*.py'
docker build -t camerahub-blink-test poc/blink
docker run --rm --entrypoint python -e PYTHONPATH=/app camerahub-blink-test -m unittest discover -s /app/tests -p 'test_*.py'
npm ci
npm run test:e2e
```

Für reale Medienpfade zusätzlich die synthetische Caddy-/MediaMTX-/H.264-
Abnahme aus `poc/acceptance/` durchführen. Nach einem Deployment `/healthz`,
Containerzustände und erwartete/bereite Quellen vergleichen. Echte Kameras nur
so weit testen, wie dies ohne unnötigen Akkuverbrauch möglich ist.

## Code Review Rules

- Änderungen beanstanden, die Akku-/On-Demand-Kameras automatisch wecken.
- Änderungen beanstanden, die Authentifizierung, CSRF, Rollenprüfung,
  Medienautorisierung oder Secret-Trennung abschwächen.
- Änderungen beanstanden, die TLS-Prüfung deaktivieren, Redirects unkontrolliert
  verfolgen oder Zugangsdaten in Logs/Payloads offenlegen.
- Änderungen beanstanden, die bestehende Kameraarten auf einen gemeinsamen
  neuen Pfad zwingen, ohne Fallback und Regressionstest.
- Änderungen beanstanden, die SQLite-Dateien im laufenden Betrieb roh kopieren
  oder destructive Migrationen ohne validierte Rückfallstrategie durchführen.
- Änderungen beanstanden, deren UI „Live“ meldet, bevor ein echter Frame oder
  ein gleichwertiger belastbarer Nachweis vorliegt.

## Definition of Done

Eine Aufgabe ist erst abgeschlossen, wenn Implementierung, relevante Tests,
Dokumentation und Rückfallweg konsistent sind, der Arbeitsbaum verstanden ist
und bestehende Kameras nicht regressiert wurden. Im Abschlussbericht immer
Branch/Commit, ausgeführte Tests, nicht praktisch prüfbare Punkte, Deployment-
Status und verbleibende Risiken nennen.
