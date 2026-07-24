# Lokales Camera-Hub-Zertifikat auf dem iPhone

Diese Anleitung gilt nur für den privaten Zugriff auf die beim Start
angegebene Host-IP, beispielsweise `https://192.168.1.50/`. Bei einer späteren öffentlichen Domain verwendet
Nginx Proxy Manager stattdessen ein öffentlich vertrauenswürdiges
Let's-Encrypt-Zertifikat.

## 1. Öffentliches Zertifikat exportieren

Auf dem Docker-Host:

```powershell
.\export-zmodo-local-ca.ps1
```

Die öffentliche Datei liegt anschließend unter:

`poc/runtime/public/PKWS-ZMODO-LOCAL-CA.cer`

Das Exportskript zeigt den aktuellen SHA-256-Fingerprint an. Nur diese
`.cer`-Datei darf auf das iPhone übertragen werden. Niemals einen privaten
Schlüssel, das Caddy-Datenvolume oder Dateien mit der Endung `.key`
übertragen.

## 2. Sicher übertragen

Die `.cer`-Datei ausschließlich innerhalb des privaten Netzes übertragen,
beispielsweise per lokalem AirDrop oder direkter lokaler Dateiübertragung.
Keinen öffentlichen Downloadlink verwenden.

Vor der Installation den angezeigten SHA-256-Fingerprint mit dem Wert auf dem
Docker-Host vergleichen.

## 3. Profil installieren

1. Die `.cer`-Datei auf dem iPhone öffnen.
2. In **Einstellungen** den Hinweis **Profil geladen** öffnen.
3. Das Profil auswählen und **Installieren** bestätigen.
4. Anschließend **Einstellungen → Allgemein → Info →
   Zertifikatsvertrauenseinstellungen** öffnen.
5. Das Vertrauen für **PKWS ZMODO Local Authority** vollständig aktivieren.

Danach Safari neu öffnen und die private HTTPS-Adresse aufrufen. Es darf
keine Zertifikatswarnung erscheinen.

## 4. Später entfernen

Unter **Einstellungen → Allgemein → VPN und Geräteverwaltung** das lokale
CA-Profil auswählen und entfernen. Danach gegebenenfalls unter
**Zertifikatsvertrauenseinstellungen** prüfen, dass kein Vertrauen mehr
aktiviert ist.

Das Entfernen auf dem iPhone löscht keine Benutzer-, Kamera- oder
Docker-Konfiguration.
