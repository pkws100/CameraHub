# CZEview Q5 – Provider-Untersuchung

## Ergebnis

Eine CZEview ZY-Q5 Akku-/Solarkamera wurde in einem ausdrücklich autorisierten
privaten Netz untersucht. Im mutmaßlichen Schlafzustand und während eines
bestätigt geöffneten Livebilds in der offiziellen CZEview-App wurde kein
reproduzierbarer lokaler ONVIF-, RTSP-, HTTP-, HTTPS-, HLS-, MJPEG- oder
Snapshot-Zugriff nachgewiesen.

Camera Hub enthält deshalb bewusst keine scheinbar funktionierende Q5-Kamera
und keinen inoffiziellen Cloud-Adapter. Ein offener Port, eine verbundene
TCP-Sitzung oder ein Herstellerhinweis wäre ohnehin kein ausreichender
Videonachweis. Für eine Integration wären echte decodierbare Frames oder ein
echter, aktueller Snapshot erforderlich.

Technische Haupteinstufung: **Klasse D – derzeit ausschließlich proprietäre
App-/Cloud-/P2P-Nutzung ohne für dieses Consumer-Gerät nachgewiesene,
freigegebene Drittanbieterschnittstelle.**

Die Einstufung kann auf Klasse C geändert werden, falls CZEview oder der
nachfolgend beschriebene Plattformanbieter einen offiziellen, für dieses
Gerät und das vorhandene Consumerkonto nutzbaren Entwicklerzugang bestätigt.

## Was belegt ist

- Das Typenschild belegt die Marke CZEview und das Modell ZY-Q5.
- Das offizielle
  [deutsche Q5-Handbuch](https://cdn.shopify.com/s/files/1/0845/1011/4101/files/Q5_Anleitung-DE.pdf?v=1772206237)
  beschreibt eine batteriebetriebene Kamera, die ausdrücklich nicht für
  24/7-Livebetrieb vorgesehen ist.
- Das Handbuch dokumentiert Livebild über die CZEview-App, Alexa,
  Zwei-Wege-Audio, Schwenken, Alarmfunktionen sowie lokale und cloudbasierte
  Ereignisspeicherung.
- Während das offizielle Livebild geöffnet war, wurde die Kamera im lokalen
  Netz nachweislich wacher und antwortete auf ICMP.
- Eine begrenzte, sequenzielle TCP-Prüfung auf typischen Web-, RTSP- und
  Kameraports fand weder im mutmaßlichen Schlafzustand noch während des
  offiziellen Livebilds einen Listener.
- Gezielte standardisierte Anfragen an ONVIF WS-Discovery, SSDP und mDNS
  blieben in beiden Zuständen ohne Antwort.
- Im geprüften Q5-Handbuch werden ONVIF, RTSP, HLS, MJPEG, ein lokaler
  Snapshot-Endpunkt oder eine Consumer-Entwickler-API nicht angeboten.

## Plattformhinweis ohne OEM-Behauptung

Die offizielle
[CZEview-App im Google Play Store](https://play.google.com/store/apps/details?id=com.czeview.net)
verweist direkt auf eine bei `meari-hz` gehostete Datenschutzrichtlinie.
Das ist ein belastbares Indiz dafür, dass die CZEview-App Infrastruktur der
Meari-Plattform verwendet.

Es beweist nicht, dass Meari Hersteller oder OEM des konkreten ZY-Q5-Geräts
ist. Ebenso sind Chipsatz, Firmwarefamilie und das tatsächliche
Medientransportprotokoll damit nicht identifiziert.

Meari veröffentlicht ein
[Developer Kit](https://github.com/Mearitek/MeariSdk). Dessen offizielle
Einrichtung verlangt jedoch einen von Meari vergebenen App Key und ein App
Secret sowie eine Cloud-Server-Integration. Ein dokumentierter Weg, ein
bestehendes CZEview-Consumerkonto oder genau dieses Q5-Modell ohne eine solche
Partnerschaft serverseitig anzubinden, wurde nicht gefunden.

Camera Hub verwendet daher weder nachgebaute App-Anmeldungen noch extrahierte
Sitzungstoken oder undokumentierte Cloud-Endpunkte.

## Schonende Testmethodik

Die Untersuchung war exakt auf ein zuvor über lokales Interface, Route und
Neighbor-Tabelle eindeutig bestimmtes Gerät begrenzt.

Verglichen wurden:

1. mutmaßlicher Schlafzustand ohne absichtlich geöffnetes Livebild;
2. Wachzustand, während der Eigentümer das Livebild etwa eine Minute in der
   offiziellen App geöffnet hielt.

Verwendet wurden nur:

- Neighbor-/Routingdaten;
- ein einzelner ICMP-Test je Zustand;
- sequenzielle TCP-Connects mit kurzen Obergrenzen;
- gezielte SSDP-, mDNS- und ONVIF-Discovery-Anfragen.

Es wurden keine Passwörter probiert, keine Stream-Pfade geraten, keine
Gerätebefehle gesendet und keine Konfiguration geändert. Ein vollständiger
Portscan wurde aus Rücksicht auf das Akkumodell nicht ausgeführt.

Ein streng gefilterter Paketmitschnitt war am Testrechner ohne erhöhte
Windows-Rechte nicht verfügbar. Außerdem kann ein gewöhnlicher kabelgebundener
LAN-Rechner direkten WLAN-Unicast zwischen Smartphone, Access Point und Kamera
nicht zuverlässig sehen. Diese Capture-Grenze wurde nicht als Protokollbefund
interpretiert.

Private IP-Adressen, MAC-Adressen, Gerätekennungen, Fotos, Befehlsausgaben und
Rohantworten liegen ausschließlich im gitignorierten lokalen Evidence-Bereich.

## Warum keine Camera-Hub-Migration angelegt wurde

Eine Datenbankmigration oder ein Provider-Platzhalter ohne nutzbare
Medienquelle würde:

- der Oberfläche eine nicht wirklich nutzbare Kamera hinzufügen;
- einen zukünftigen Providervertrag vorzeitig auf unbestätigte Annahmen
  festlegen;
- falsche Erwartungen an Wake-up, Status und Live-Leases erzeugen;
- neue Sicherheitsfläche ohne tatsächlichen Nutzen schaffen.

Der bestehende ONVIF-/RTSP-/HLS-/MJPEG-/Snapshot-Pfad bleibt unverändert.
Ebenso bleiben die sechs bestehenden Kameraquellen, ihre Reihenfolge,
Verbindungsrevisionen, Leases und Relays unberührt.

## Erforderlicher offizieller nächster Schritt

CZEview sollte schriftlich folgende Fragen beantworten:

1. Unterstützt ZY-Q5 einen lokalen ONVIF-, RTSP- oder Snapshot-Zugriff?
2. Falls ja: In welchem Firmwarestand und nur während welcher Wachzustände?
3. Ist ZY-Q5 mit dem offiziellen Meari Developer Kit nutzbar?
4. Kann ein bestehendes CZEview-Consumerkonto rechtmäßig mit einer
   serverseitigen Partneranwendung verknüpft werden?
5. Welche App-Key-/App-Secret-, OAuth- oder Partnerfreigabe ist erforderlich?
6. Gibt es eine dokumentierte Operation für Snapshot, Live-Session,
   Keepalive und kontrolliertes Session-Ende?
7. Welche Limits und maximale Sitzungsdauer gelten für Akkukameras?

Nur bei positiver Bestätigung sollte ein serverseitiger Provider-Adapter
entwickelt werden.

## Zielvertrag für eine spätere offizielle Integration

Ein späterer Adapter muss mindestens diese Operationen kapseln:

- `discover_devices()`
- `get_device_status()`
- `resolve_snapshot()`
- `start_live_session()`
- `resolve_live_source()`
- `keep_live_session()`
- `stop_live_session()`
- `refresh_authentication()`
- `get_capabilities()`

Vorgaben:

- Ausführung ausschließlich im Backend;
- Tokens und temporäre Quellen AES-GCM-verschlüsselt;
- keine Geräteadresse, Token oder Provider-URL im Browser;
- Livebild nur nach ausdrücklichem Benutzeraufruf;
- begrenztes Wake-up-Backoff ohne Dauer-Restart;
- kurze konfigurierbare Maximalsitzung;
- Lease-Ende stoppt Provider- und Relay-Sitzung;
- Snapshot und Medienantworten mit `Cache-Control: no-store`;
- Status `schläft` darf nicht als dauerhafter Systemfehler erscheinen;
- keine automatische Leitstellenkachel oder Vorschau-Aktualisierung, die die
  Kamera dauerhaft wachhält.

## Deinstallation

Es wurde keine Kamera- oder Providerintegration installiert. Zur Entfernung
dieser Untersuchung genügt das Löschen dieses Dokuments. Lokale Evidence kann
unabhängig davon aus dem ignorierten Runtime-Verzeichnis entfernt werden.
