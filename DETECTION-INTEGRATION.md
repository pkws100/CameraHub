# Lokale Alarmzonenerkennung

## Sicherheits- und Datenschutzmodell

Camera Hub 1.5.0 ergänzt einen getrennten Dienst `detection-worker`. Er erhält
weder Kamerazugangsdaten noch Datenbankzugriff und veröffentlicht keinen Port.
Ein eigener, zufälliger Adapter-Schlüssel schützt seine interne Verbindung zum
Backend. Der Container läuft ohne Root-Rechte, ohne Linux-Capabilities, mit
schreibgeschütztem Dateisystem und festen CPU-/Speichergrenzen.

Der Worker liest ausschließlich durch das Backend freigegebene, bereits
laufende MediaMTX-Dauerstreams über internes RTSP/TCP. Cloud-, Akku-, Snapshot-
und On-Demand-Kameras sind serverseitig ausgeschlossen. Deshalb erzeugt die
Erkennung keine Wake-, Lease-, Snapshot- oder Hersteller-Cloud-Aufrufe.

Rohbilder werden nur im Arbeitsspeicher verarbeitet. Normalerweise speichert
Camera Hub ausschließlich Bewegungsmetadaten. Das optionale Beweisbild wird je
Zone bewusst aktiviert, auf JPEG, 640×360 Pixel und 256 KB begrenzt und mit
AES-GCM verschlüsselt. Es wird nicht exportiert und nach spätestens sieben
Tagen beziehungsweise beim globalen 500-MB-Limit älteste-zuerst gelöscht.
Bewegungsmetadaten werden nach 90 Tagen beziehungsweise oberhalb von 100.000
Einträgen bereinigt.

## Betriebsarten

- **Aus:** Der Worker beendet alle FFmpeg-Leser innerhalb von zehn Sekunden.
- **Beobachten:** Bewegungen werden als Ereignisse protokolliert; Browseralarm
  und Webhooks bleiben stumm.
- **Scharf:** Bewegungen erzeugen zusätzlich angemeldete Browseralarme und
  ausgewählte, HMAC-signierte `zone.motion`-Webhooks.

Die Migration aktiviert weder bestehende noch neue Zonen. Ein Alarm erfordert
gleichzeitig eine aktive globale Betriebsart, Kamera und Alarmzone sowie
gegebenenfalls ein aktives Kamera- und Zonenzeitfenster. Kein Zeitfenster
bedeutet „immer aktiv“. Die Auswertung verwendet standardmäßig
`Europe/Berlin`, einschließlich Sommer- und Winterzeit.

## Erkennungsablauf

Pro Kamera liest FFmpeg drei Graustufenbilder pro Sekunde in 640×360 Pixeln.
OpenCV lernt zunächst zehn Sekunden lang den Hintergrund. Danach gelten
standardmäßig:

- Empfindlichkeit 50 von 100
- mindestens 1,5 Prozent veränderte Zonenfläche
- eine Sekunde bestätigte Bewegung
- fünf Sekunden Ruhe bis zum Ereignisende
- 30 Sekunden Sperre bis zum nächsten neuen Alarm

Eine Änderung von mehr als 60 Prozent des Gesamtbilds wird als Lichtwechsel
oder Kamerabewegung behandelt. Camera Hub beendet ein gegebenenfalls offenes
Ereignis kontrolliert, lernt den Hintergrund neu und erzeugt keinen Alarm.
Ausschlusszonen werden vor der Prüfung aus der Bewegungsmaske entfernt.

Der Worker verwendet für ein Ereignis eine stabile ID. Wiederholungen sind
dadurch im Backend dedupliziert; laufende Bewegungen werden höchstens alle fünf
Sekunden aktualisiert und nach der Ruhezeit genau einmal beendet. Fehlt der
Worker-Heartbeat länger als 20 Sekunden, schließt das Backend offene
Bewegungsereignisse kontrolliert.

## Oberfläche

Der Eigentümer wählt unter **Systemstatus → Alarmzonenerkennung** die
Betriebsart und sieht Workerzustand, aktive Kameras, Verzögerung,
CPU-/Speichernutzung und den letzten Fehler. Browseralarm und Ton werden je
Browser bewusst aktiviert; die Quittierung bleibt lokal.

Eigentümer und Administratoren konfigurieren unter **Alarmzonen** die
Kameraaktivierung, Zonenparameter, Beweisbilder und Wochenzeitpläne.
Nicht unterstützte On-Demand-Kameras werden verständlich gekennzeichnet und
können nicht aktiviert werden. Bewegungsereignisse erscheinen in der
Ereignisansicht. Gekoppelte Nur-Lese-Anzeigegeräte erhalten in 1.5.0 keine
Alarmbanner.

## Einführung und Rückfall

1. Nach dem Update bleibt die globale Betriebsart **Aus**.
2. Zunächst nur einzelne lokale Dauerstream-Kameras aktivieren.
3. Mindestens 48 Stunden im Modus **Beobachten** Empfindlichkeit und
   Fehlalarme bewerten.
4. Anschließend geeignete Zonen einzeln **Scharf** schalten und bei Bedarf
   `zone.motion` am Webhook-Ziel auswählen.

Der sofortige Rückfall ist jederzeit **Aus**. Dadurch enden alle
Erkennungsleser. Danach kann `detection-worker` aus der Docker-Konfiguration
entfernt werden; Kamera-, MediaMTX-, Benutzer-, Ereignis- und Webhookfunktionen
bleiben bestehen.

## Abnahme

Die CI prüft Algorithmusfälle, Migration und Rollen, Token-Isolation,
verschlüsselte Bilder, Ereignisdeduplizierung, Beobachten/Scharf,
HMAC-Webhooks und vollständige Browserregression. Der synthetische
Docker-Test verwendet echte H.264-Quellen, Caddy und MediaMTX, analysiert
sieben Dauerstreams parallel und prüft weiterhin Raster mit bis zu elf
Kameras, WebRTC und HLS.

Die reale 48-Stunden-Beobachtung mit den Kameras des Betreibers ist bewusst
eine Freigabebedingung und kein durch einen kurzen CI-Lauf ersetzbarer Test.
