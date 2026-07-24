# Camera Hub auf einem privaten Docker-Host

## Privater HTTP-Betrieb für Fernseher und lokale Geräte

Für ein ausdrücklich vertrauenswürdiges, durch die Windows-Firewall begrenztes
LAN kann Camera Hub vollständig über einen gemeinsamen HTTP-Origin laufen:

```powershell
.\start-zmodo-pwa.ps1 -Mode HttpTest -LanAddress 192.168.1.50
.\enable-zmodo-test-firewall.ps1 -Mode HttpTest `
  -BindAddress 192.168.1.50 -RemoteAddress 192.168.1.0/24
```

Die Beispiel-URL lautet `http://192.168.1.50:8090/`. PWA, API, WHEP und HLS laufen
über den lokalen Caddy-Gateway. Die MediaMTX-Webports bleiben intern. Im LAN
werden nur TCP 8090 sowie der für WebRTC benötigte Medienport 8189/TCP+UDP
freigegeben. Für nicht vertrauenswürdige Netze, öffentliche Zugriffe und
WireGuard-Gateways ist stattdessen HTTPS zu verwenden.

## Lokaler HTTPS-Betrieb

Der sichere Hostmodus bindet ausschließlich an eine konkret vorhandene private
IPv4-Adresse. Beispiel:

```powershell
.\start-zmodo-pwa.ps1 -Mode Https -LanAddress 192.168.1.50
```

Danach lautet die Adresse:

`https://192.168.1.50/`

Öffentlich erreichbar werden dadurch keine Dienste. Docker veröffentlicht nur:

- TCP 443 für PWA, API, WHEP-Signalisierung und HLS über Caddy;
- TCP/UDP 8189 für WebRTC-Medien.

Für Wartung direkt auf dem Docker-Host bleiben zusätzlich die bisherigen
Loopback-Bindungen `127.0.0.1:8090`, `:8888` und `:8889` erhalten. Sie sind von
anderen Geräten nicht erreichbar.

Web, MediaMTX-API, interner RTSP-Port, Kamera-RTSP, Relay-UDP-Ports,
Datenbank und Secretdateien bleiben im Docker-Netz.

## Windows-Firewall

Die Freigabe muss einmal in einer als Administrator gestarteten PowerShell
ausgeführt werden:

```powershell
.\enable-zmodo-private-access.ps1 `
  -BindAddress 192.168.1.50 `
  -RemoteAddress 192.168.1.0/24
```

Das Skript lehnt `Any`, öffentliche Adressen und `0.0.0.0/0` ab. Es erstellt
nur Regeln mit dem Präfix `PKWS-ZMODO-PWA-`, nur für das Profil `Private`, die
konkrete lokale IP und die genannten privaten Quellnetze.

Für einen späteren WireGuard-Bereich muss dessen konkretes privates Subnetz
zusätzlich angegeben werden. Beispiel ausschließlich nach bestätigter
WireGuard-Konfiguration:

```powershell
.\enable-zmodo-private-access.ps1 `
  -BindAddress 192.168.1.50 `
  -RemoteAddress 192.168.1.0/24,10.77.0.0/24
```

## Lokales Zertifikat

Caddy erstellt eine lokale CA mit einem Zertifikat für die konkrete IP-Adresse.
Nur das öffentliche Stammzertifikat wird exportiert:

```powershell
.\export-zmodo-local-ca.ps1
```

Der private CA-Schlüssel bleibt im persistenten, nicht versionierten
Caddy-Volume. Er darf nicht auf Mobilgeräte, den VPS oder in ein Repository
übertragen werden.

## Rollback

```powershell
.\remove-zmodo-test-firewall.ps1
.\start-zmodo-pwa.ps1 -Mode Loopback
```

Der vollständige vorbereitete Rollback ist:

```powershell
.\rollback-zmodo-lan-test.ps1
```

Volumes, Benutzer, Kamerakonfiguration und Zertifikatsdaten werden dabei nicht
gelöscht.

## IONOS-VPS und Nginx Proxy Manager

Empfohlener Datenweg:

`Browser → öffentliches HTTPS am Nginx Proxy Manager → WireGuard → Caddy auf dem privaten Docker-Host → Camera Hub`

Dabei gelten folgende Grenzen:

- keine Router-Portfreigabe zum Docker-Host;
- der VPS erreicht den Host ausschließlich über WireGuard;
- Nginx Proxy Manager verwendet ein öffentlich vertrauenswürdiges Zertifikat;
- nur das konkrete WireGuard-Subnetz wird in der Hostfirewall ergänzt;
- Kamera- und RTSP-Ports werden niemals durch den Tunnel veröffentlicht;
- die App-Anmeldung bleibt zusätzlich zur Proxy-Absicherung aktiv;
- HLS funktioniert vollständig über den HTTPS-Reverse-Proxy.

WebRTC benötigt außer der WHEP-Signalisierung einen für den Browser
erreichbaren ICE-/Medienpfad. Eine private Adresse wie `192.168.1.50:8189` ist
für einen beliebigen Internetbrowser nicht direkt erreichbar. Für die erste
öffentliche Version ist daher HLS der sichere Rückfallweg. Öffentliches WebRTC
erfordert später entweder MediaMTX/TURN auf dem VPS oder eine sehr eng
begrenzte öffentliche UDP-Architektur am VPS; es darf nicht durch eine
Routerfreigabe zum Kameranetz gelöst werden.
