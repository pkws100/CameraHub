# Betriebsabnahme

Die Abnahme besteht aus drei voneinander getrennten Stufen. Keine Stufe
kontaktiert eine echte Akku- oder Cloudkamera ohne eine ausdrücklich geöffnete
Liveansicht.

## 1. Schnelle Regression

Im Repository-Stamm:

```powershell
npm ci
npm run test:e2e
```

Diese Tests verwenden ausschließlich nachgebildete APIs und prüfen Desktop,
Tablet und Mobilgerät: Raster mit 1, 2, 4, 6 und 11 Kameras, HLS-Frame-Gating,
deaktivierte Kameras, Profilqualität, Anzeigegeräte, Kopplung und
Ruhebildschirm.

## 2. Echter Medienpfad

```powershell
.\poc\acceptance\Start-SyntheticAcceptance.ps1
```

Das Skript baut eine wegwerfbare Umgebung aus elf synthetischen
H.264-Dauerquellen, MediaMTX, Camera Hub und dem echten Caddy-Gateway. Geprüft
werden die Rastergrößen, passive MediaMTX-Zustände, WHEP-Autorisierung,
HLS-Playlist und -Segment sowie „Live“ erst nach einem wirklichen HLS-Frame.
Testschlüssel liegen nur unter dem ignorierten `poc/runtime/` und der Stack
wird anschließend einschließlich seines Testvolumes entfernt.

## 3. 24-Stunden-Betriebsabnahme

```powershell
.\poc\acceptance\Start-24HourAcceptance.ps1 `
  -BaseUrl http://192.168.1.50:8090 `
  -DurationHours 24
```

Das Skript fragt nach einem Camera-Hub-Konto und verwendet danach nur
`/healthz`, `/api/health` sowie einmalig den passiven Kamerakatalog. Es ruft
keinen Lease-, Wake-, Snapshot- oder Stream-Endpunkt auf. CZEview, Netatmo und
andere On-Demand-Kameras werden aus der Verfügbarkeitsberechnung entfernt.

Die bereinigte JSONL-Datei enthält nur gehashte Kamerareferenzen, Zustand und
Zeitstempel. Die Zusammenfassung verlangt mindestens 99 Prozent Verfügbarkeit
je lokalem Dauerstream, höchstens 90 Sekunden beobachtete Erholungszeit, keine
offene HLS-Sitzung am Ende und kein auffälliges Wachstum des
Backend-Arbeitsspeichers (mehr als 25 Prozent beziehungsweise 128 MiB).
Beide Dateien entstehen unter `poc/runtime/acceptance/` und werden nicht
versioniert.

Während des Laufs werden Camera Hub, MediaMTX und Relay-Manager jeweils einmal
kontrolliert neu gestartet. Die Uhrzeit jedes Neustarts wird im
Abnahmeprotokoll des Betreibers festgehalten; die passive Messung bestimmt die
Erholungszeit. Backend-Speicher und aggregierte MediaMTX-Sitzungszahlen werden
über dieselbe angemeldete, passive Statusantwort protokolliert.

## Freigaberegeln

`v1.3.3` darf erst gesetzt werden, wenn CI, Wiederherstellungstest und die
vollständige 24-Stunden-Abnahme bestanden sind. `v1.4.0` benötigt zusätzlich
48 Stunden praktische Anzeige auf mindestens einem Tablet und einem Fernseher.
Außerhalb aktiver Zeitfenster muss der Ruhebildschirm sichtbar sein und es
dürfen keine Kamera-, Vorschaubild- oder Lease-Aufrufe entstehen.

Ein fehlender Langzeittest ist kein technischer Fehler, aber eine
Freigabesperre. Deshalb erzeugen die Skripte selbst weder Git-Tags noch
GitHub-Releases.
