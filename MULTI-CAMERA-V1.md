# Multi-Kamera-PWA Version 1

## Betriebsmodell

Eine optionale lokale Startkonfiguration wird beim ersten Datenbankstart
idempotent in SQLite übernommen. Neu angelegte Kameras erhalten neutrale Pfade
und werden vom internen Relay-Manager verwaltet. Der Manager kann dynamische
MediaMTX-Pfade anlegen, besitzt aber keinen Docker-Socket. Statische
VLC-Relays bleiben als ausdrücklich aktivierbarer Legacy-Rollbackpfad erhalten.

Der Eigentümer richtet die Anmeldung ausschließlich über Loopback ein. Erst
danach darf der HTTPS-Modus für WLAN oder VPN aktiviert werden. Schreibende
Verwaltungsendpunkte lehnen unverschlüsselten Zugriff von Nicht-Loopback-
Adressen mit HTTP 426 ab.

## Kamera-Assistent

1. Eigentümer bestätigt sein Passwort.
2. Die App startet einen begrenzten Scan im fest konfigurierten privaten Netz.
3. WS-Discovery-Treffer und Geräte mit standardisiertem ONVIF/RTSP erscheinen
   in einer flüchtigen Ergebnisliste. Lesbare ONVIF-Profile zeigen Codec und
   Auflösung. Eine lesbare Snapshot-URI wird ausschließlich serverseitig
   gehalten und über einen authentifizierten `no-store`-Endpunkt angezeigt.
4. Der Eigentümer wählt ein Gerät oder gibt eine erlaubte Adresse manuell ein.
5. Ein kurzer `ffprobe`-Test muss echte Videopakete bestätigen.
6. Erst danach werden Kamera, Profile und verschlüsselte Zugangsdaten lokal
   gespeichert.

Automatische Pfad-Wortlisten und Herstellerpasswörter werden nicht verwendet.
Ohne Anmeldung lesbare ONVIF-Streampfade werden in den Assistenten übernommen.
Geräte, die ONVIF-Metadaten erst nach Authentifizierung liefern, bleiben über
die validierte manuelle RTSP-, HLS-, MJPEG- oder Snapshot-Einrichtung nutzbar.

## API-Oberflächen

Viewer:

- `GET /api/cameras`
- `GET /api/health`
- `GET /api/cameras/{id}/status`
- `POST|DELETE /api/cameras/{id}/lease`

Eigentümerverwaltung:

- `/api/auth/state`, `/login`, `/logout`, `/reauth`, `/setup`
- `/api/auth/change-password`
- `/api/admin/users` und `/api/admin/users/{id}`
- `/api/admin/users/{id}/password`
- `/api/admin/discovery/scans`
- `/api/admin/discovery/scans/{id}/devices/{device}/preview`
- `/api/admin/cameras`, `/test-source`, `/order`
- `/api/admin/cameras/{id}/preview`
- `/api/admin/cameras/{id}/zones`
- `GET|PUT /api/admin/cameras/{id}/connection`
- `POST /api/admin/cameras/{id}/connection/test`
- `POST /api/admin/cameras/{id}/connection/activate`
- `POST /api/admin/cameras/{id}/connection/rollback`
- `GET /api/admin/cameras/{id}/capabilities`
- `POST /api/admin/cameras/{id}/capabilities/refresh`
- `POST /api/admin/cameras/{id}/ptz/move`
- `POST /api/admin/cameras/{id}/ptz/stop`
- `POST /api/admin/cameras/{id}/ptz/presets/{token}/goto`

Intern, nicht über den Reverse Proxy vorgesehen:

- `GET /internal/v1/relay-config`
- `GET /internal/v1/detection/cameras`
- `POST /internal/v1/events` – in Version 1 deaktiviert

Viewer-Antworten enthalten keine Geräte-IP. Administrative Antworten dürfen
für die Einrichtung IP, Hersteller und Modell enthalten, niemals aber
Kennwörter oder vollständige authentifizierte Streamadressen.

## Verbindungsrevisionen und ONVIF-Funktionen

Eine Kamera kann gemeinsame Zugangsdaten oder getrennte Zugänge für ONVIF und
den Stream besitzen. Neue Angaben werden als Entwurf gespeichert. Leere
Zugangsfelder übernehmen auf Wunsch den vorhandenen verschlüsselten Zugang;
kein API-Endpunkt gibt ihn zurück. Der Verbindungstest unterscheidet ONVIF,
Hauptstream, Substream und Audiospur und verlangt echte Videopakete.

Nach einer Aktivierung überwacht das Backend die Revision 60 Sekunden. Bleiben
Videopakete aus, wird automatisch die vorherige funktionierende Revision
eingesetzt. Die Oberfläche kennzeichnet, ob eine aktive Revision bereits vom
dynamischen Relay verwendet oder als Rollbackpfad vorgemerkt wird.

Die Funktionsmatrix wird ausschließlich über offene ONVIF-Leseoperationen
gebildet. Unterstützt werden HTTP Basic/Digest und WS-Security
UsernameToken/PasswordDigest. PTZ nutzt nur ContinuousMove, Stop und den
Aufruf vorhandener Presets. Presets, Imaging, Benutzer, Netzwerk, Firmware,
Aufzeichnung und Geräteausgänge werden nicht verändert.

## Rollen und Sitzungen

Das bei der Migration vorhandene Konto wird idempotent als `owner` übernommen.
Eigentümer dürfen Benutzer und Rollen verwalten. Administratoren dürfen Kameras,
Discovery, Reihenfolge und Zonen verwalten. Betrachter erhalten ausschließlich
Liveansicht, Medienautorisierung und Systemstatus. Die Prüfung erfolgt auf jedem
API-Endpunkt serverseitig; ausgeblendete Menüpunkte sind nur eine zusätzliche
Oberflächenhilfe. Rollenänderung, Deaktivierung und Passwortzurücksetzung
widerrufen bestehende Sitzungen des betroffenen Kontos. Das letzte aktive
Eigentümerkonto kann nicht entfernt oder herabgestuft werden.

## Zonenformat

Zonen bestehen aus mindestens drei normalisierten Punkten `{x,y}` zwischen
`0` und `1`. `kind` ist `alarm` oder `ignore`. Jede Speicherung erhöht eine
Revision; konkurrierende Änderungen werden mit HTTP 409 abgewiesen. Die spätere
Erkennungsengine erhält dieselben Koordinaten über die interne Adapter-API.

## Bekannte Grenzen

- Die aktive Erkennungsengine und Alarmereignisse sind nicht Bestandteil von V1.
- H.265/MJPEG-Transcoding ist CPU-basiert und muss pro Kameramodell gemessen
  werden; es wird nicht dauerhaft gestartet.
- Bestehende statische Quellen sollten erst nach einem erfolgreichen
  30-Minuten-Parallellauf des dynamischen Managers abgeschaltet werden.
- Physische iPhone-, Home-Screen- und VPN-Abnahme benötigt weiterhin die
  manuelle lokale Zertifikatsinstallation und die bereits vorbereitete, eng
  begrenzte Windows-Freigabe.
