# Camera Hub 1.3.3

Camera Hub 1.3.3 ist die Betriebsabnahme des stabilen 1.3-Zweigs. Der Release
ändert keine Kamera- oder Cloudprotokolle, sondern macht ihre Regression
reproduzierbar.

## Inhalt

- automatische Rasterprüfung mit 1, 2, 4, 6 und 11 Kameras auf Desktop,
  Tablet und Mobilgerät;
- Prüfung von deaktivierten Kameras, Profilreihenfolge, Haupt-/Substream,
  WebRTC, HLS-Weiterleitung und echtem Frame-Gating;
- wegwerfbarer Stack aus elf H.264-Quellen, MediaMTX, Camera Hub und dem
  produktionsgleichen Caddy-Pfad;
- verbindliche CZEview-Brückentests in GitHub Actions;
- automatisierter verschlüsselter Backup-/Restore-Vergleich einschließlich
  Benutzer, Rollen, Kameras, Cloud-Konten, Profile, Zonen, Ereignisse und
  Webhooks;
- passives 24-Stunden-Skript mit bereinigten Kamerareferenzen, mindestens
  99 Prozent Dauerstream-Verfügbarkeit und höchstens 90 Sekunden Erholung.

## Freigabesperre

Diese Notizen sind vorbereitet, aber noch kein veröffentlichter Release. Tag
und GitHub-Release dürfen erst entstehen, wenn CI, praktische
Wiederherstellung und der vollständige 24-Stunden-Lauf bestanden sind. Das
Skript weckt keine CZEview-, Netatmo- oder andere On-Demand-Kamera.
