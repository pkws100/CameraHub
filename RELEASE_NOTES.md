# Camera Hub 1.3.0

Camera Hub 1.3.0 macht den bestehenden Multi-Kamera-Hub für den dauerhaften
privaten Betrieb besser nachvollziehbar und wiederherstellbar.

## Höhepunkte

- passiv ermittelte, dauerhafte Betriebsereignisse mit fünfminütiger
  Störungsschwelle und eindeutiger Entwarnung;
- verständliche Zustände für Livebild, Verbindungsaufbau, schlafende
  On-Demand-Kameras, Kameraausfall, Cloud-Neuanmeldung und Medienserverfehler;
- portable, mit Scrypt und AES-256-GCM geschützte Sicherungsarchive;
- geprüfte Wiederherstellung mit lokaler Rückfallsicherung,
  Neuverschlüsselung der Geheimnisse und Widerruf aller Sitzungen;
- HMAC-SHA-256-signierte Webhooks mit Ereignisfilter, Testzustellung,
  Geheimnisrotation und begrenzten Wiederholungen;
- neue Eigentümerfunktionen auf der Systemseite, ohne Änderungen an den
  bestehenden Kamera-, Cloud-, Benutzer-, Profil- oder Lease-Abläufen.

## Wichtige Hinweise

- Die Backup-Passphrase wird nicht gespeichert und muss außerhalb von Camera
  Hub sicher verwahrt werden.
- Laufzeitsitzungen, Videodaten und CZEview-Sitzungscaches sind bewusst nicht
  Teil eines Backups.
- Die Überwachung weckt keine Akku- oder On-Demand-Kamera. Erst ein
  fehlgeschlagener, ausdrücklich angeforderter Zugriff wird bewertet.
- Webhook-Geheimnisse werden nur bei Anlage oder Erneuerung vollständig
  angezeigt.

Installations-, Betriebs- und Sicherheitshinweise stehen in
[README.md](README.md), [OPERATIONS.md](OPERATIONS.md) und
[SECURITY.md](SECURITY.md).
