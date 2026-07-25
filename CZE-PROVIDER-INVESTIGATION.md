# CZEview-Akku-/Solarkamera – historischer Zwischenstand

Dieses Dokument hält den ersten, bewusst schonenden Untersuchungsstand fest.
Im Schlafzustand und während eines in der offiziellen App geöffneten Livebilds
wurde kein reproduzierbarer lokaler ONVIF-, RTSP-, HTTP-, HTTPS-, HLS-,
MJPEG- oder Snapshot-Dienst nachgewiesen.

Die vollständige Geräteadresse wurde nicht aus der bekannten Endung geraten,
sondern aus aktivem Interface, Routingtabelle und Neighbor-Zuordnung ermittelt.
Standort-IP, vollständige MAC-Adresse, Gerätekennungen und Rohantworten bleiben
im ignorierten lokalen Evidence-Bereich.

Dieser Zwischenstand ist inzwischen technisch überholt: Mit den vom Betreiber
bereitgestellten CZEview-Kontodaten wurden die CZEview-App-/Mandantenkennung,
Cloud-Wake, ein echtes H.264-Livebild, Snapshots und die horizontale Steuerung
praktisch bestätigt. Camera Hub besitzt deshalb nun eine optionale,
bedarfsgesteuerte P2P-Brücke.

Der aktuelle, reproduzierbare Befund, die Sicherheitsgrenzen und die
Einrichtung stehen in
[CZEVIEW-INTEGRATION.md](CZEVIEW-INTEGRATION.md).

Die lokale Untersuchung beweist weiterhin keinen bestimmten Kamera-OEM,
Produktnamen oder SoC. Die belegte Meari-Plattformzugehörigkeit darf nicht als
Herstellerbehauptung für das konkrete Gerät verstanden werden.