# CZEview-Akku-/Solarkamera

## Ergebnis und Evidenz

Die untersuchte Kamera ist über den CZEview-App-Zugang erreichbar. Der
reproduzierbare Medienweg lautet:

`CZEview-Konto → Meari-P2P-Signalisierung → H.264 → CZEview-Brücke → MediaMTX → WebRTC/HLS/Snapshot`

Am 25. Juli 2026 wurden dabei echte Videoframes und ein durch Camera Hub
erzeugter Snapshot bestätigt:

- H.264 High Profile;
- 2304 × 1296 Pixel;
- CZEview-API-Gerätetyp `5`;
- Ruhezustand, Cloud-Wake und anschließender Onlinezustand;
- funktionierender On-Demand-Stream bis zum geschützten Camera-Hub-Snapshot;
- horizontaler Schwenk über die Gerätekonfiguration `841` mit Stopp über
  `842`, jeweils praktisch an der untersuchten Kamera bestätigt.

Die vollständige lokale Adresse wurde nicht aus der bekannten Endung geraten.
Das aktive lokale Interface, die zugehörige Route und die Neighbor-Tabelle
wurden gemeinsam ausgewertet; erst die Neighbor-Zuordnung lieferte die
vollständige Adresse zur Endung .108. Standort-IP und vollständige MAC-Adresse
bleiben lokale Evidenz und werden nicht in das öffentliche Repository
übernommen. Der offizielle IEEE-OUI-Eintrag nennt für das ermittelte Präfix
AltoBeam Inc. Das belegt den Anbieter des WLAN-Chips beziehungsweise -Moduls,
nicht den Kamera-OEM.

Während eines Wachfensters wurde kein üblicher lokaler HTTP-, RTSP- oder
ONVIF-Dienst nachgewiesen. Ein vollständiger negativer All-Port-Nachweis liegt
nicht vor. Der belastbar funktionierende Weg ist deshalb die von der
CZEview-App verwendete P2P-Plattform.

Die offiziellen CZEview-App-Verträge liegen unter der App-/Mandantenkennung
`141` auf Meari-Infrastruktur. Die Anmeldung mit `sourceApp=141`, Geräteabfrage,
Wake-Funktion und P2P-Livebild wurden praktisch bestätigt. Damit ist die
Meari-Plattformzugehörigkeit bewiesen. Ein bestimmter Kamera-OEM, ein
Produktname wie „Q6“ oder eine bestimmte SoC-Familie sind damit weiterhin
nicht bewiesen und werden nicht behauptet.

## Einrichtung

Empfohlen wird ein eigenes CZEview-Betrachterkonto, an das die Kamera in der
App freigegeben wird. Die Plattform erlaubt praktisch nur eine aktive Sitzung
pro Konto; eine Anmeldung der Brücke kann daher die Mobil-App desselben Kontos
abmelden.

Die Zugangsdaten bleiben ausschließlich in der ignorierten Datei
`poc/.env`:

```dotenv
CZEVIEW_USEREMAIL=betrachter@example.com
CZEVIEW_PASSWORD=lokales-geheimnis
CZEVIEW_COUNTRY_CODE=DE
CZEVIEW_PHONE_CODE=+49
CZEVIEW_SOURCE_APP=141
```

Optionale Werte:

```dotenv
CZEVIEW_CAMERA_NAME=CZEview Garten
CZEVIEW_DEVICE_SERIAL=vollstaendige-seriennummer-nur-bei-mehreren-kameras
```

`CZEVIEW_DEVICE_SERIAL` ist nur nötig, wenn das Konto mehr als eine Kamera
enthält. Die Seriennummer darf nicht in Git eingecheckt werden.

Der normale Start erkennt die vollständige CZEview-Konfiguration und aktiviert
das optionale Compose-Profil automatisch:

```powershell
.\start-zmodo-pwa.ps1 -Mode Loopback
```

Beim Start werden nur die benötigten CZEview-Felder in eine ACL-geschützte
Runtime-Secret-Datei übertragen. Das Passwort erscheint weder in Browser-APIs
noch in Camera-Hub-Protokollen. Der Plattform-Token liegt in einem separaten
Docker-Volume.

## Betriebsverhalten

Die Kamera wird nicht dauerhaft wach gehalten. Beim Öffnen einer Kachel oder
Detailansicht erstellt Camera Hub einen erneuerbaren Lease. Die Brücke weckt
die Kamera, baut das P2P-Fenster auf und veröffentlicht einen neutralen
MediaMTX-Pfad. Nach dem Schließen der Ansicht wird der Lease freigegeben und
die Brücke beendet den Publisher.

Die kurzen H.264-Fenster der Akku-Kamera werden mit 15 Bildern pro Sekunde und
häufigen Schlüsselbildern neu codiert. Dadurch können WebRTC-, HLS- und
Snapshot-Leser auch nach Beginn eines P2P-Fensters zuverlässig einsteigen.
Auf dem ersten Verbindungsaufbau sind mehrere Sekunden Wake-Zeit normal.
Ein direkter Snapshot-Aufruf erstellt ebenfalls nur für die Dauer der
Frame-Erfassung einen temporären Lease und gibt ihn anschließend wieder frei.

Die Integration ist cloud-unterstützt, nicht rein lokal: Für Anmeldung, Wake
und Signalisierung müssen die CZEview/Meari-Dienste erreichbar sein.

Für Eigentümer und Administratoren ist ausschließlich der nachgewiesene,
zeitlich begrenzte horizontale Schwenk freigeschaltet. Camera Hub übermittelt
dazu begrenzte Links-/Rechtsvektoren an einen nur im internen Compose-Netz
erreichbaren, mit Service-Token geschützten Adapter und sendet beim Loslassen
einen Stoppbefehl. Vertikale Bewegung, Zoom, Kalibrierung, Presets, Audio,
Gegensprechen, Sirene und Licht sind nicht freigeschaltet. Bestehende
ONVIF-PTZ-Funktionen anderer Kameras bleiben unverändert.

## Reproduzierbare Prüfungen

Backend-Regressionstest:

```powershell
docker build -t camera-hub-backend-test poc/backend
docker run --rm -e PYTHONPATH=/app --entrypoint python `
  camera-hub-backend-test /app/tests/integration.py
docker build -t camera-hub-czeview-test poc/czeview
docker run --rm -e PYTHONPATH=/app --entrypoint python `
  camera-hub-czeview-test -m unittest discover -s /app/tests
```

Compose- und Syntaxprüfung:

```powershell
docker compose -f poc/docker-compose.yml config --quiet
python -m py_compile poc/backend/app.py poc/czeview/bridge.py
node --check poc/web/app.js
```

Ein echter End-to-End-Test muss mit dem autorisierten Konto erfolgen. Als
Erfolgskriterien gelten ein aktiver MediaMTX-Pfad, ein von
`/api/cameras/czeview/snapshot` geliefertes JPEG, ein abgespieltes
WebRTC-Livebild und angenommene Links-/Rechts-/Stoppbefehle über Camera Hub.
Aufnahmen und standortbezogene Evidence bleiben im ignorierten
Runtime-Verzeichnis.

Die vertiefte Analyse zu Sitzungscache, Wake-up, Mobil-App-Wechselwirkung und
der behobenen Neuanmeldeschleife steht in
[CZEVIEW-SESSION-STABILITY-REPORT.md](CZEVIEW-SESSION-STABILITY-REPORT.md).
