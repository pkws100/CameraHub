# Netatmo-Integration

Camera Hub 1.1 verbindet Netatmo-Konten ausschließlich über den offiziellen
OAuth-Autorisierungscodefluss. Das Netatmo-Passwort wird weder abgefragt noch
gespeichert.

## Einrichtung

1. In Netatmo Connect eine App anlegen.
2. Als Rücksprungadresse exakt die in Camera Hub angezeigte Adresse eintragen,
   beispielsweise
   `http://192.168.178.160:8090/api/cloud/oauth/netatmo/callback`.
3. Als Eigentümer **Kameras suchen → Cloud-Konten → Netatmo einrichten**
   öffnen und Client-ID, Client-Geheimnis und Rücksprungadresse speichern.
4. **Netatmo-Konto** wählen und die Anmeldung bei Netatmo abschließen.
5. Eine neue Kamerasuche starten. Vor dem Hinzufügen muss jede Kamera über
   **Streams & Vorschau prüfen** einen echten Videoframe liefern.

Camera Hub fordert nur lesende Kamera- und Zugriffsrechte an:
`read_camera`, `access_camera`, `read_presence`, `access_presence`,
`read_doorbell`, `access_doorbell` und `read_camerapro`.

## Technische Grenzen

- Inventar und Status werden über `homesdata` und `homestatus` gelesen.
- Livezugriff wird aus dem von Netatmo gelieferten `vpn_url` abgeleitet und
  nur innerhalb des internen Netatmo-Adapters verarbeitet.
- Browser und öffentliche API erhalten weder OAuth-Token noch `vpn_url`.
- Der Adapter besitzt keinen Host-Port und keinen Docker-Socket.
- Livebilder werden nur bei einem aktiven Camera-Hub-Lease angefordert.
- Netatmo Indoor Camera Advance (`NPC`) bleibt deaktiviert, solange der
  öffentliche Drittanbieterzugriff keinen realen Frame liefert.
- Flutlicht, Sirene, Türsteuerung und andere schreibende Funktionen sind nicht
  Bestandteil dieser Integration.

OAuth-Zustände sind einmalig und zehn Minuten gültig. Zugriffs- und
Erneuerungstoken werden mit dem bestehenden Camera-Hub-Schlüssel verschlüsselt.
Ein Konto kann nicht gelöscht werden, solange eine Kamera damit verknüpft ist.
