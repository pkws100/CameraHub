# Abschlussbericht: Cloud-Konten und Mehrkonto-Suche

Stand: Entwicklungsstand für Camera Hub 1.1.0

## Ergebnis

Camera Hub verwaltet mehrere CZEview- und Netatmo-Konten getrennt und verwendet
alle aktivierten Konten zusammen mit der lokalen ONVIF-/RTSP-Suche. Ein Fehler
in einem Konto beendet die Suche der übrigen Konten nicht. Gefundene
Cloud-Kameras werden erst nach einem echten Videoframe-Nachweis zum Hinzufügen
freigegeben.

Die Kontoübersicht steht dem Eigentümer unter **Kameras suchen →
Cloud-Konten** zur Verfügung. Dort kann jedes Konto:

- umbenannt,
- aktiviert oder deaktiviert,
- mit neuen Zugangsdaten beziehungsweise einer neuen OAuth-Anmeldung verbunden
  und
- entfernt werden, sofern keine Kamera mehr damit verknüpft ist.

Ein Administrator kann eine Suche mit den vom Eigentümer aktivierten Konten
starten, erhält aber keinen Zugriff auf Konto-Geheimnisse oder
Provider-Konfigurationen. Betrachter sehen weder Suche noch Kontoverwaltung.

## CZEview

Beim Hinzufügen eines CZEview-Kontos werden Bezeichnung, Benutzername,
E-Mail-Adresse, Passwort, Länderkennung, Telefonvorwahl und App-Kennung
entgegengenommen. Benutzername und E-Mail-Adresse sind getrennte Felder. Die
Anmeldedaten werden verschlüsselt gespeichert und nur dem isolierten
CZEview-Adapter über eine interne, authentisierte Schnittstelle bereitgestellt.

**Zugang erneuern** ersetzt die verschlüsselten Anmeldedaten eines vorhandenen
Kontos. Gerätebestand, Kamera-Zuordnungen und Camera-Hub-Kamera-ID bleiben
erhalten. Der laufende Kontoprozess erkennt die Änderung, beendet die alte
Sitzung kontrolliert und meldet sich mit dem neuen Stand wieder an.

Die untersuchte Akku-/Solarkamera bleibt bedarfsgesteuert: Camera Hub weckt sie
erst für Vorschau, Snapshot oder Liveansicht. Pro CZEview-Konto ist höchstens
ein Akku-Kamerastream gleichzeitig aktiv. Nach Ablauf des Leases wird die
Übertragung beendet.

### Erneute reale Prüfung

Am 26. Juli 2026 meldete sich der Adapter erfolgreich am bestehenden Konto an
und fand ein Gerät. Anschließend wurden mehrere echte H.264-Übertragungsfenster
empfangen, unter anderem:

- 32 Videobilder / 371.394 Byte,
- 40 Videobilder / 335.244 Byte,
- 30 Videobilder / 351.001 Byte.

Damit sind Cloud-Anmeldung, Gerätezuordnung und realer Videotransport erneut
bestätigt. Nach den Übertragungen war der Media-Pfad erwartungsgemäß nicht
dauerhaft aktiv; das entspricht dem Akkuschutz und ist kein Fehlerzustand.

## Netatmo

Netatmo wird ausschließlich über den offiziellen OAuth-Autorisierungscodefluss
verbunden. Camera Hub fragt das Netatmo-Passwort nicht ab und speichert es
nicht.

### Daten in Camera Hub eintragen

1. In Netatmo Connect eine eigene App anlegen.
2. Als Rücksprungadresse exakt
   `http://192.168.178.160:8090/api/cloud/oauth/netatmo/callback` eintragen,
   solange diese lokale Camera-Hub-Adresse verwendet wird.
3. In Camera Hub als Eigentümer **Kameras suchen → Cloud-Konten → Netatmo
   einrichten** öffnen.
4. Client-ID, Client-Geheimnis und dieselbe Rücksprungadresse speichern.
5. **Netatmo-Konto** wählen, eine verständliche Bezeichnung vergeben und die
   offizielle Netatmo-Anmeldung abschließen.
6. Für jedes weitere Netatmo-Konto Schritt 5 wiederholen.
7. **Nach Kameras suchen** starten. Camera Hub fragt alle aktivierten
   Netatmo- und CZEview-Konten sowie das konfigurierte private LAN ab.
8. Die gewünschte Netatmo-Kamera mit **Streams & Vorschau prüfen** testen. Erst
   ein echter Videoframe schaltet das Hinzufügen frei.

Wenn Netatmo den Zugriff widerruft oder ein Erneuerungstoken nicht mehr gültig
ist, wird **Neu verbinden** am bestehenden Konto verwendet. Der OAuth-Zustand
ist einmalig und zehn Minuten gültig. Bei erfolgreicher Rückkehr werden Token
und Bezeichnung im vorhandenen Datensatz ersetzt; Geräte- und
Kamera-Zuordnungen bleiben erhalten.

### Angeforderte Rechte

Camera Hub fordert die lesenden Kamera- und Zugriffsrechte `read_camera`,
`access_camera`, `read_presence`, `access_presence`, `read_doorbell`,
`access_doorbell` und `read_camerapro` an. Flutlicht, Sirene, Türsteuerung und
andere schreibende Herstellerfunktionen gehören nicht zur Integration.

## Such- und Importverhalten

Eine Suche erzeugt eine gemeinsame Ergebnisliste:

1. Lokale Geräte werden nur innerhalb des ausdrücklich konfigurierten privaten
   Netzes über die bestehenden ONVIF-/RTSP-Prüfungen untersucht.
2. Jedes aktivierte Cloud-Konto wird unabhängig inventarisiert.
3. Anbieter, Konto, Modell, Verfügbarkeit und Stream-Unterstützung bleiben je
   Ergebnis sichtbar.
4. Ein Konto im Fehler- oder Neuanmeldungszustand wird gekennzeichnet, ohne
   andere Konten oder die LAN-Suche abzubrechen.
5. Cloud-Geräte mit nicht bestätigtem Livezugriff bleiben sichtbar, können aber
   nicht ungeprüft importiert werden.
6. Beim Import bleibt die Kamera fest dem betreffenden Konto und Gerät
   zugeordnet.

## Sicherheitsgrenzen

- Zugangsdaten, OAuth-Zugriffs- und Erneuerungstoken sowie die
  Netatmo-Client-Konfiguration liegen verschlüsselt in SQLite.
- Browser und öffentliche API erhalten weder entschlüsselte Geheimnisse noch
  Netatmo-`vpn_url`-Werte.
- CZEview- und Netatmo-Adapter verwenden getrennte interne Dienst-Tokens.
- Die Adapter veröffentlichen keine Host-Ports und besitzen keinen Zugriff auf
  den Docker-Socket.
- Kontoverwaltung und Provider-Konfiguration sind Eigentümerfunktionen.
- OAuth-Zustände sind gehasht, einmalig und zehn Minuten gültig.
- Ein Konto mit verknüpften Kameras kann nicht versehentlich gelöscht werden.
- Erneuerte CZEview-Zugangsdaten und Netatmo-Token werden in-place ersetzt;
  dadurch entstehen keine verwaisten Kamera-Zuordnungen.

## Verifikation und Regression

Der Backend-Integrationstest deckt unter anderem ab:

- Schema-Migration bis Version 5,
- Verschlüsselung der Cloud-Geheimnisse,
- mehrere Provider und Kontentrennung,
- Ersetzen von CZEview-Zugangsdaten ohne Verlust von Gerät oder Kamera,
- Netatmo-Wiederverbindung ohne doppeltes Konto,
- Netatmo-Callback, Inventarmodelle und Stream-Allowlist,
- Frame-gesteuerten Cloud-Import,
- Rollen, CSRF-Schutz, Sitzungswiderruf, Kamera-Leases, PTZ,
  Verbindungsrevisionen und Rollback.

Die CZEview-Adaptertests bestätigen zusätzlich die begrenzten horizontalen
PTZ-Befehle und die Unterstützung der nachgewiesenen Steuerungsvarianten.
JavaScript- und Python-Syntaxprüfungen sowie die Container-Builds gehören zur
Abnahme.

Die bestehenden Zmodo-, ONVIF-, RTSP-, HLS-, MJPEG-, Snapshot-, MediaMTX-,
WebRTC-, Benutzer-, Rollen-, Lease- und Sicherheitswege werden nicht durch
provider-spezifische Sonderfälle ersetzt. Die Cloud-Adapter ergänzen diese
Wege über den vorhandenen neutralen External-Camera-Vertrag.

## Offene reale Netatmo-Abnahme

Die technische Netatmo-Mehrkonto- und OAuth-Kette ist implementiert und mit
simulierten Provider-Antworten reproduzierbar getestet. Eine reale
Ende-zu-Ende-Abnahme benötigt noch die Betreiber-Client-ID, das
Client-Geheimnis und die interaktive Freigabe des jeweiligen Netatmo-Kontos.

Für die nächste Abnahme gelten folgende Erfolgskriterien:

- jedes gewünschte Netatmo-Konto erscheint genau einmal als **Verbunden**;
- die gemeinsame Suche zeigt die Kameras aller aktivierten Konten;
- ein Konto lässt sich deaktivieren, ohne die übrigen Suchergebnisse zu
  beeinflussen;
- **Neu verbinden** erhält vorhandene Kamera-Zuordnungen;
- eine unterstützte Kamera liefert im Vorschautest einen echten Frame;
- Liveansicht, Lease-Ende und erneutes Aufwecken funktionieren;
- ein Modell ohne öffentlichen Drittanbieter-Livezugriff bleibt ehrlich als
  nicht importierbar gekennzeichnet.

Erst nach diesem realen Frame-Nachweis wird ein konkretes Netatmo-Modell als
vollständig livebildfähig dokumentiert.
