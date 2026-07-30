# PKWS Camera Hub

Lokales, herstellerneutrales Multi-Kamera-Gateway für ONVIF-, RTSP-, HLS-,
Snapshot- und MJPEG-Kameras. Camera Hub verbindet standardisierte Kameras mit
einer geschützten PWA und WebRTC/HLS-Ausgabe. Der Kern benötigt keine
proprietären Hersteller-Plug-ins. Für CZEview-Akku-Kameras und freigegebene
Netatmo-Sicherheitskameras stehen getrennte, bedarfsgesteuerte Cloud-Adapter
bereit.

> **Entwicklungsstand 1.5.0:** Dieser Stand ist für einen selbst verwalteten
> privaten Docker-Host vorgesehen. Vor einer Erreichbarkeit über das Internet
> müssen WireGuard, ein HTTPS-Reverse-Proxy und eine zusätzliche
> Netzsegmentierung eingerichtet werden.

## Lokaler Start

```powershell
.\start-zmodo-pwa.ps1 -Mode Loopback
```

Die App ist anschließend unter `http://127.0.0.1:8090/` erreichbar. Beim ersten
Start werden Benutzername und ein mindestens acht Zeichen langes Passwort für
den Eigentümer festgelegt. Diese erstmalige Kontoanlage ist ausschließlich über
Loopback möglich. Nach der Einrichtung zeigt die App nur noch die normale
Anmeldung mit Benutzername und Passwort.

Der Start erzeugt die benötigten lokalen Schlüsseldateien unter
`poc/runtime/secrets/`. Sie verschlüsseln Kamera-Zugangsdaten und
Bewegungsbilder und schützen die voneinander getrennten internen APIs. Das gesamte
Runtime-Verzeichnis ist ignoriert. Ein Verlust des Kameraschlüssels macht
verschlüsselte Zugangsdaten unlesbar; deshalb gehört es in ein geschütztes,
lokales Backup.

Stoppen und Status:

```powershell
.\stop-zmodo-pwa.ps1
.\status-zmodo-pwa.ps1
```

## Cloud-Konten und Akku-Kameras

Die untersuchte CZEview-Kamera besitzt keinen nachgewiesenen lokalen
RTSP-/ONVIF-Dienst. Camera Hub kann ihr bestätigtes H.264-Livebild stattdessen
über eine optionale, bedarfsgesteuerte P2P-Brücke beziehen. Die Kamera wird
erst beim Öffnen der Ansicht geweckt und nach Freigabe des Leases nicht
dauerhaft wach gehalten.

Neue Konten werden als Eigentümer unter **Kameras suchen → Cloud-Konten**
angelegt. Mehrere CZEview- und Netatmo-Konten können parallel aktiviert werden.
Jede Cloud-Kamera muss vor dem Hinzufügen einen echten Frame-Test bestehen.
Geräte ohne freigegebenen Livezugriff bleiben sichtbar, aber deaktiviert.
Konten lassen sich dort umbenennen, einzeln aktivieren oder deaktivieren.
CZEview-Zugangsdaten können erneuert und bestehende Netatmo-Konten erneut über
den offiziellen Netatmo-Login verbunden werden, ohne Kamera-Zuordnungen oder
Kontoduplikate zu erzeugen.

Bestehende CZEview-Einträge in der ignorierten `poc/.env` werden einmalig in
den verschlüsselten Kontospeicher übernommen. Einrichtung, Sicherheitsgrenzen,
Ein-Sitzungs-Hinweis und technische Evidenz stehen in
[CZEVIEW-INTEGRATION.md](CZEVIEW-INTEGRATION.md).
Die vertiefte Analyse zu Sitzungscache, Wake-up und Wiederanmeldung steht in
[CZEVIEW-SESSION-STABILITY-REPORT.md](CZEVIEW-SESSION-STABILITY-REPORT.md).
Die Netatmo-App-Einrichtung und die bewusst begrenzten Rechte beschreibt
[NETATMO-INTEGRATION.md](NETATMO-INTEGRATION.md).
Der geprüfte Gesamtstand der Mehrkonto-Verwaltung ist in
[CLOUD-ACCOUNT-COMPLETION-REPORT.md](CLOUD-ACCOUNT-COMPLETION-REPORT.md)
dokumentiert.

## Lokale Alarmzonenerkennung

Der optionale Dienst `detection-worker` liest ausschließlich bereits laufende
MediaMTX-Dauerstreams. Akku-, Cloud-, Snapshot- und andere On-Demand-Kameras
werden serverseitig ausgeschlossen und dadurch nicht zusätzlich geweckt. Die
Erkennung startet nach der Migration immer in der Betriebsart **Aus**.

Unter **Alarmzonen** lassen sich unterstützte Kameras und einzelne Alarmzonen
aktivieren, Empfindlichkeit, Mindestfläche, Bestätigungs-, Ruhe- und Sperrzeit
festlegen sowie Wochenzeitfenster konfigurieren. Unter **Systemstatus** stehen
die Betriebsarten **Aus**, **Beobachten** und **Scharf** zur Verfügung.
Beobachten speichert nur Bewegungsmetadaten; erst Scharf sendet Browseralarme
und ausgewählte HMAC-Webhooks. Beweisbilder sind je Zone optional, auf
640×360 Pixel und 256 KB begrenzt, verschlüsselt und nicht Bestandteil von
Sicherungen.

Architektur, Datenschutzgrenzen, Einführung und Rückfall beschreibt
[DETECTION-INTEGRATION.md](DETECTION-INTEGRATION.md).

## Betriebssicherheit

Unter **Systemstatus** zeigt Camera Hub dauerhafte Betriebsereignisse mit
offenen, beobachteten und behobenen Störungen. Lokale Dauerstreams werden
passiv über MediaMTX ausgewertet. Akku- und On-Demand-Kameras werden von der
Überwachung nicht selbstständig geweckt; nur ein tatsächlich fehlgeschlagener,
vom Benutzer angeforderter Zugriff erzeugt ein Signal.

Eigentümer können dort portable Sicherungen herunterladen und wiederherstellen.
Das Archiv wird mit einer mindestens zwölf Zeichen langen, ausschließlich vom
Betreiber verwahrten Passphrase verschlüsselt. Vor der Wiederherstellung werden
Archiv, Prüfsumme und Datenbankschema geprüft und ein lokaler Rückfallpunkt
angelegt. Alle Sitzungen werden danach beendet.

Ebenfalls im Eigentümerbereich lassen sich Webhook-Ziele verwalten. Meldungen
werden mit HMAC-SHA-256 signiert, folgen keinen Weiterleitungen und enthalten
keine Zugangsdaten oder internen Stream-Adressen. Einzelheiten zu Archivformat,
Signaturprüfung und Fehlerverhalten stehen in
[OPERATIONS.md](OPERATIONS.md).

## Gekoppelte Anzeigegeräte

Eigentümer verwalten unter **Systemstatus → Anzeigegeräte** eigene
Nur-Lese-Zugänge für Tablets und Fernseher. Ein achtstelliger Code ist zehn
Minuten und genau einmal gültig. Nach der Kopplung öffnet das Gerät
`/display.html`; eine normale Benutzeranmeldung und Verwaltungsrechte erhält
es nicht.

Einem Gerät können mehrere Anzeigeprofile in Prioritätsreihenfolge zugewiesen
werden. Pro Kamera speichert das Profil `Automatisch`, `Hauptstream`,
`Substream` oder `HLS-Hauptstream`. Wiederkehrende Wochenzeitfenster werden in
`Europe/Berlin` ausgewertet; `CAMERA_HUB_TIMEZONE` kann diese Zeitzone ändern.
Zeiträume über Mitternacht und Sommer-/Winterzeit werden berücksichtigt.

Ist kein Zeitfenster aktiv, zeigt das Gerät ausschließlich seinen privaten
Ruhebildschirm mit Uhrzeit und nächstem Profilstart. Dabei werden keine
Kameradaten, Vorschaubilder oder Leases geladen. Geräte können gesperrt, erneut
gekoppelt oder vollständig widerrufen werden. Sicherungen erhalten
Gerätekonfiguration und Zeitpläne, aber keine Gerätesitzungen.

## Zugriff über die private IP

Der sichere Docker-Host-Modus wird an eine konkrete private IP gebunden:

```powershell
.\start-zmodo-pwa.ps1 -Mode Https -LanAddress 192.168.1.50
```

Die App ist dann beispielsweise unter `https://192.168.1.50/` erreichbar. Die eng
begrenzte Windows-Firewallfreigabe wird einmal in einer administrativen
PowerShell eingerichtet:

```powershell
.\enable-zmodo-private-access.ps1 `
  -BindAddress 192.168.1.50 `
  -RemoteAddress 192.168.1.0/24
```

Dabei werden nur HTTPS 443 und WebRTC TCP/UDP 8189 freigegeben. Eine Anleitung
für den privaten Docker-Host und den späteren WireGuard-/VPS-Weg steht in
[PRIVATE-DOCKER-HOST.md](PRIVATE-DOCKER-HOST.md). Die lokale
iPhone-Zertifikatsinstallation steht in
[IPHONE-LOCAL-CA-INSTALLATION.md](IPHONE-LOCAL-CA-INSTALLATION.md).

Im HTTPS-Modus bleiben die MediaMTX-Webports 8888/8889 vollständig intern.
HLS und WHEP sind ausschließlich über den angemeldeten gemeinsamen
HTTPS-Origin erreichbar.

Für Fernseher und andere Geräte in einem ausdrücklich vertrauenswürdigen
privaten LAN kann der Modus `HttpTest` als vollständiger privater HTTP-Gateway
verwendet werden:

```powershell
.\start-zmodo-pwa.ps1 -Mode HttpTest -LanAddress 192.168.1.50
.\enable-zmodo-test-firewall.ps1 -Mode HttpTest `
  -BindAddress 192.168.1.50 -RemoteAddress 192.168.1.0/24
```

PWA, API, HLS und WHEP teilen dann beispielsweise `http://192.168.1.50:8090/`.
Das Startskript leitet das für HTTP-Verwaltung zulässige Netz aus der bestätigten
LAN-Adresse und ihrer aktiven Präfixlänge ab; innerhalb dieses ausdrücklich
ausgewählten privaten Netzes besteht keine HTTPS-Pflicht. MediaMTX-Webports
bleiben intern; zusätzlich zu TCP 8090 ist nur der WebRTC-Medienport
8189/TCP+UDP für das konkrete private Netz freigegeben.
Dieser Modus besitzt transportbedingt keinen Secure Context und sollte nicht
über öffentliche oder unzuverlässige Netze angeboten werden.

## Funktionen der Multi-Kamera-Version

- animiertes, barrierearmes Burger-Menü;
- geschützte Liveansicht und Eigentümerverwaltung;
- persönliche Anzeigeprofile je Benutzer mit eigener Kameraauswahl,
  Kachelreihenfolge, Wochenzeitplänen, kamerabezogener Streamqualität und
  geschützten Startlinks;
- gekoppelte, widerrufbare Nur-Lese-Anzeigegeräte mit Ruhebildschirm;
- optionaler Leitstellenmodus mit randlosem, automatisch angepasstem
  Mehrkamera-Raster und derselben persönlichen Profilauswahl;
- rollenbasierte Benutzerverwaltung mit Eigentümer, Administrator und Betrachter;
- SQLite-Persistenz für Kameras, Reihenfolge und Polygonzonen;
- konservative Suche im ausdrücklich konfigurierten privaten Netz über
  WS-Discovery, ONVIF und RTSP;
- manueller RTSP-, HLS-, MJPEG- und Snapshot-Assistent mit echtem Frame-Test;
- versionierte Kamera-Verbindungen mit gemeinsamem oder getrenntem
  ONVIF-/Stream-Zugang, verschlüsselten Entwürfen, Prüfung, Aktivierung und
  Rückkehr zur letzten funktionierenden Revision;
- ONVIF-Profil-, Codec- und Auflösungsanzeige sowie flüchtige No-Store-Vorschau, sofern das Gerät diese Daten ohne Konfigurationsänderung bereitstellt;
- TP-Link-Tapo-Erkennung über den dokumentierten ONVIF-Port 2020 mit
  bearbeitbaren `stream1`-/`stream2`-Vorschlägen und verschlüsseltem
  Kamerakonto; Details stehen in [TAPO-C220.md](TAPO-C220.md);
- lesende ONVIF-Funktionsmatrix für Audio, PTZ, vorhandene Presets, Events,
  Analytics und Geräteausgänge; nur vorhandene PTZ-Presets können aufgerufen
  werden, Gegensprechen und physische Ausgänge bleiben deaktiviert;
- H.264-Stream-Copy, bedarfsgesteuerter H.265-/MJPEG-Kompatibilitätsweg;
- optionale CZEview-P2P-Brücke mit Wake-on-View, erneuerbarem Lease und
  nachgewiesenem horizontalem Schwenk;
- mehrere verschlüsselte CZEview- und Netatmo-Konten in einer gemeinsamen
  LAN-/Cloud-Suche;
- Netatmo-OAuth ohne Speicherung des Netatmo-Passworts und ein
  bedarfsgesteuerter, intern isolierter HLS-Adapter;
- dynamischer Relay-Manager ohne Docker-Socket;
- Detection-Adaptervertrag, standardmäßig deaktiviert;
- Service Worker ausschließlich für statische App-Dateien.

Der Browser erhält neutrale Streamnamen. Kamera-Passwörter, authentifizierte
RTSP-Adressen und interne Tokens werden nicht ausgeliefert. Details stehen in
[MULTI-CAMERA-V1.md](MULTI-CAMERA-V1.md), Sicherheitsgrenzen in
[SECURITY.md](SECURITY.md). Standortbezogene Untersuchungsberichte und
Netzwerk-Evidence sind bewusst nicht Bestandteil des öffentlichen Repositorys.

Rollen:

- **Eigentümer:** Benutzer, Kameras, Suche, Zonen und Liveansicht;
- **Administrator:** Kameras, Suche, Zonen und Liveansicht;
- **Betrachter:** Liveansicht und Systemstatus.

Benutzeränderungen verlangen eine erneute Bestätigung des Eigentümerpassworts.
Das eigene Passwort kann jede angemeldete Person im Systemstatus ändern.

### Leitstellenmodus

Die Schaltfläche **Leitstellenmodus** in der Liveübersicht wechselt in eine
randlose Großbildansicht. Bei sechs Kameras wird auf einem Querformatbildschirm
ein lückenloses 3×2-Raster verwendet; Hochformat und andere Kameraanzahlen
werden automatisch angepasst. Kamera- und Live-Status bleiben als dezente
Einblendung sichtbar, die normalen Steuerelemente werden ausgeblendet.

Jeder angemeldete Benutzer kann in der Liveübersicht persönliche
**Anzeigeprofile** mit eigener Kamerareihenfolge pflegen. Ein Profil gilt nur
für dieses Benutzerkonto und ist keine zusätzliche Kameraberechtigung.
Deaktivierte Kameras bleiben im Profil gespeichert, werden aber in Live- und
Leitstellenansicht ausgeblendet. Nach ihrer Reaktivierung erscheinen sie wieder
an der gespeicherten Position.

Über **Profile verwalten** lassen sich geschützte Startlinks für die normale
Liveansicht und den Leitstellenmodus kopieren. Beispiele:

```text
http://camera-hub/#overview?profile=<Profil-ID>
http://camera-hub/#wall?profile=<Profil-ID>
```

Ist noch keine gültige Sitzung vorhanden, erscheint zuerst die normale
Anmeldung. Ein fremdes oder gelöschtes Profil fällt ohne Datenfreigabe auf
**Alle aktiven Kameras** zurück. Für Fernseher und Tablets entstehen dadurch
keine anonymen Kiosk-Zugänge. Für unbeaufsichtigte Displays steht stattdessen
der ausdrücklich gekoppelte Nur-Lese-Zugang unter `/display.html` bereit.

Die Schaltfläche **Normalansicht** erscheint kurz beim Wechsel sowie nach
Zeiger- oder Touchbewegung und blendet sich anschließend aus. Alternativ
beendet `Escape` den Modus. Die Adresse mit `#wall` kann auf einem
Leitstellenbildschirm als Lesezeichen verwendet werden. Browser-Vollbild wird
beim direkten Wechsel angefordert; wenn ein Browser das nicht unterstützt,
bleibt die randlose App-Ansicht trotzdem aktiv.

## Streamingkette und Legacy-Kompatibilität

Einige ältere RTSP-Server benötigen regelmäßige Sessionaktivität. Für solche
Geräte steht der erprobte Legacy-Weg bereit:

`Zmodo RTSP/TCP → VLC/live555 → MPEG-TS/UDP intern → MediaMTX → WebRTC/HLS → PWA`

H.264 wird nicht neu codiert. Neue Kameras werden über die verschlüsselte
Kameraverwaltung und den dynamischen Relay-Manager eingebunden. Die optionalen
statischen Relay-Profile dienen ausschließlich als lokaler Migrations- und
Rollbackpfad; ihre Quelladressen gehören nur in die ignorierte `.env`.

Camera Hub verändert weder Kamera-, Receiver-, Router- noch
Aufzeichnungseinstellungen.

## Automatische Abnahme

Desktop-, Tablet- und Mobiltests sowie der echte Caddy-/MediaMTX-/H.264-Pfad
laufen in GitHub Actions. Die lokale 24-Stunden-Abnahme fragt ausschließlich
passive Statusdaten ab und schließt Akku-/Cloudkameras aus. Befehle,
Freigabekriterien und bereinigte Protokolle beschreibt
[poc/acceptance/README.md](poc/acceptance/README.md).

## Akku-/Cloudkameras

Akkukameras werden nicht automatisch wie dauerhaft erreichbare RTSP-Kameras
behandelt. Die erste Schlaf-/Wach-Untersuchung fand keinen lokalen
Standarddienst. Der anschließend mit dem bekannten CZEview-Konto praktisch
bestätigte P2P-Zugriff ermöglicht heute eine lease-basierte, optionale
Integration. Der historische Zwischenstand steht in
[CZE-PROVIDER-INVESTIGATION.md](CZE-PROVIDER-INVESTIGATION.md), der aktuelle
Betrieb in [CZEVIEW-INTEGRATION.md](CZEVIEW-INTEGRATION.md).

## Lizenz
Camera Hub wird unter der [GNU Affero General Public License v3.0](LICENSE)
bereitgestellt. Die Software kommt ohne Gewährleistung; Details stehen in der
Lizenzdatei.
