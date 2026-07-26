# CZEview-Sitzungs- und Wake-up-Analyse

Stand: 26. Juli 2026

## Kurzfazit

Ein täglicher Wechsel des Cloud-Tokens ist technisch möglich, aber für den
beobachteten Vorfall nicht als Hauptursache bewiesen. Die verwendete
Drittbibliothek behandelt ihren lokalen Sitzungscache nach 24 Stunden als
abgelaufen. Das ist eine clientseitige Festlegung und kein Nachweis einer
serverseitigen Token-Lebensdauer.

Zwei lokale Ursachen konnten dagegen eindeutig nachgewiesen werden:

1. Der erste Mehrkonto-Adapter verwendete einen neuen kontospezifischen
   Cachepfad, ohne den vorhandenen gültigen Legacy-Cache zu übernehmen. Dadurch
   wurde vor Ablauf von 24 Stunden ein neuer Cloud-Login ausgeführt.
2. Die erste Fassung der Zugangsdaten-Erneuerung deutete den allgemeinen
   Kontozeitstempel fälschlich als Zugangsdatenrevision. Da jede erfolgreiche
   Geräte-Inventur diesen Zeitstempel aktualisiert, beendete und startete der
   Kontoprozess ungefähr alle 20 Sekunden neu.

Beide Ursachen sind behoben.

## Beobachtete Zeitlinie

- Der Legacy-Sitzungscache enthielt eine Anmeldung vom
  25. Juli 2026, 21:50:44 UTC.
- Der kontospezifische Cache enthielt eine Anmeldung vom
  26. Juli 2026, 12:17:55 UTC.
- Beim zweiten Login war der erste Cache erst rund 14,5 Stunden alt und damit
  noch innerhalb des von der Bibliothek verwendeten 24-Stunden-Fensters.
- Beide Cachedateien gehörten zur gleichen Benutzer-ID, enthielten aber
  unterschiedliche Tokens.
- Vor der Korrektur meldete Camera Hub im Abstand von ungefähr 20 Sekunden
  erneut `authenticated`.
- Nach der Korrektur gab es während mehrerer Prüfintervalle genau einen
  Sitzungsstart und genau eine Anmeldung. Der vorhandene Cache wurde als
  `fresh` mit einem Alter von rund 0,22 Stunden erkannt.

Es wurden keine Tokenwerte protokolliert oder in diesen Bericht übernommen.

## Was beim Öffnen der Mobil-App passiert sein kann

Das zeitliche Verhalten lässt drei Effekte zu, die getrennt betrachtet werden
müssen.

### 1. Akku-Kamera wurde geweckt

Die untersuchte Kamera ist nach Betreiberangabe ein Akku-/Solargerät. CZEview
listet für seine öffentlich gezeigten Akku-Modelle C2F und E5 keine
24/7-Aufzeichnung; das passt zum beobachteten Schlafverhalten, beweist aber
keine konkrete Modellzuordnung. Die verwendete P2P-Implementierung
unterscheidet zwischen `dormancy` und `online`, sendet bei Bedarf ein
Wake-Signal und wartet bis zu 30 Sekunden auf das Gerät. Ein Öffnen der
Hersteller-App kann denselben Wake-up-Pfad auslösen. Wenn Camera Hub kurz
danach erneut verbindet, ist die Kamera bereits online.

Bewertung: **wahrscheinlich**.

### 2. Geräte- oder P2P-Metadaten wurden aktualisiert

Die Drittbibliothek bezeichnet sich selbst als Beta und dokumentiert, dass
Status beziehungsweise Refresh zeitweise erst aktualisiert werden, wenn die
Mobil-App geöffnet wurde. Vor jedem Stream liest Camera Hub die
kontospezifischen Gerätekennungen und Host-Metadaten erneut. Die Hersteller-App
kann deshalb einen zuvor veralteten Cloud-/Signalisierungszustand aktualisiert
haben.

Bewertung: **wahrscheinlich**, aber mangels offizieller Protokollspezifikation
nicht isoliert beweisbar.

### 3. Ein neuer Login ersetzte einen anderen Sitzungstoken

Der lokal nachgewiesene zweite Login erzeugte für dieselbe Benutzer-ID einen
anderen Token. Gleichzeitig wurde beobachtet, dass die Mobil-App nach einem
Camera-Hub-Login erneut eine Anmeldung verlangte. Das passt zu einer Plattform,
die nur einen oder eine begrenzte Zahl aktiver Tokens je Konto zulässt.

Eine offizielle CZEview-Dokumentation zu parallelen Sitzungen liegt nicht vor.
Deshalb wird dieser Zusammenhang als starke Indikation, nicht als bewiesene
Herstellergarantie dokumentiert.

Bewertung: **gut möglich**.

## Die 24-Stunden-Frage

Die eingesetzte Bibliothek `pycloudedge 0.1.7` speichert `loginTime` zusammen
mit Benutzer-ID, Token und regionalen API-Endpunkten. Beim Laden gilt:

- jünger als 24 Stunden: Cache wird ohne vorherige Servervalidierung verwendet;
- älter als 24 Stunden: Cache wird verworfen und ein neuer Login ausgeführt.

Das bedeutet:

- Ja, nach 24 Stunden führt der aktuelle Client planmäßig einen neuen Login
  aus.
- Nein, daraus folgt nicht, dass der Servertoken exakt täglich abläuft.
- Meldet sich die Mobil-App zwischenzeitlich neu an und entwertet dabei einen
  älteren Token, kann Camera Hub bis zur nächsten echten API-Anfrage zunächst
  einen lokal „frischen“, serverseitig aber möglicherweise ungültigen Token
  halten.

Quellennachweis:

- <https://github.com/fradaloisio/pycloudedge/blob/main/cloudedge/client.py>
- <https://github.com/fradaloisio/pycloudedge>
- <https://czeview.net/products/czeview-c2f>

Die Bibliothek ist nicht offiziell mit CZEview verbunden und beschreibt sich
selbst als reverse-engineerte Beta. Aus API-Pfadnamen allein wird deshalb keine
OEM- oder Plattformidentität der Kamera abgeleitet.

## Behobene Camera-Hub-Ursachen

### Eigene Zugangsdatenrevision

Schema-Migration 6 ergänzt `auth_revision`. Nur ein tatsächlicher Austausch der
verschlüsselten Zugangsdaten erhöht diese Zahl. Geräte-Inventur,
Statusaktualisierung und `last_verified_at` verändern sie nicht.

Der Adapter hält einen Kontoprozess deshalb stabil am Leben und startet ihn nur
neu, wenn:

- das Konto deaktiviert wird,
- die Zugangsdaten wirklich erneuert werden oder
- der Dienst kontrolliert neu gestartet wird.

### Übernahme des vorhandenen Sitzungscaches

Bei der einmaligen Migration eines Legacy-Kontos aus `poc/.env` wird ein
vorhandener Sitzungscache in den kontospezifischen Pfad übernommen. Ein
unnötiger zusätzlicher Cloud-Login und eine mögliche Abmeldung der Mobil-App
werden damit vermieden.

### Kontrollierte Fehlererholung

Vorher löschte bereits der erste allgemeine `CloudEdgeError` den Cache. Nun
gilt:

- Netzwerk- und Backendfehler löschen keinen Cloud-Token.
- Ein einzelner Providerfehler wird als vorübergehend markiert.
- Erst drei aufeinanderfolgende Kontofehler lösen eine kontrollierte
  Neuanmeldung aus.
- Cache-Resets sind auf höchstens einen je 30 Minuten begrenzt.
- Ein expliziter Authentifizierungsfehler benötigt nicht erst drei Fehlversuche,
  unterliegt aber ebenfalls der 30-Minuten-Begrenzung.

Die Protokollierung enthält künftig nur Cachezustand, Cachealter,
Fehlerkategorie und einen begrenzten Fehlercode. Tokens, Benutzername,
E-Mail-Adresse und Passwort werden nicht protokolliert.

## Verbleibende technische Grenzen

Akku- und Cloud-Kameras bleiben grundsätzlich weniger deterministisch als eine
lokale ONVIF-/RTSP-Kamera:

- Die Kamera kann schlafen und benötigt einen Wake-up.
- Mobil-App und Camera Hub können um denselben Cloud-/P2P-Zustand konkurrieren.
- Ein P2P-Livefenster liefert bei diesem Gerät typischerweise nur ungefähr
  15 bis 20 Sekunden Video und muss anschließend sauber neu aufgebaut werden.
- Cloud-, Signalisierungs- oder TURN-Dienste können vorübergehend nicht
  verfügbar sein.
- Die tatsächliche serverseitige Token-Lebensdauer und das Limit paralleler
  Sitzungen sind nicht offiziell dokumentiert.

Camera Hub kann diese Grenzen nicht entfernen, aber unnötige Logins,
aggressive Tokenlöschung und falsche Prozessneustarts vermeiden.

## Abnahmekriterien

Die Korrektur gilt als technisch bestätigt, wenn:

- nach einem Adapterstart genau ein `session_start` und ein `authenticated`
  erscheinen;
- im Leerlauf keine Anmeldung im 20-Sekunden-Takt mehr auftritt;
- eine normale Inventur `auth_revision` nicht verändert;
- Zugangsdaten-Erneuerung `auth_revision` genau einmal erhöht;
- ein einzelner Providerfehler den Cache nicht löscht;
- drei fortlaufende Kontofehler eine begrenzte Wiederanmeldung erlauben;
- Livebild, Lease-Ende und erneutes Wake-up weiter funktionieren;
- bestehende Zmodo-, Netatmo-, ONVIF-, RTSP-, HLS-, WebRTC- und
  MediaMTX-Wege unverändert bleiben.
