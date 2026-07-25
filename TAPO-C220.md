# TP-Link Tapo C220

Camera Hub unterstützt die Tapo C220 ausschließlich über ihre offenen
Standardschnittstellen. Es wird weder die Tapo-Cloud noch ein proprietäres
TP-Link-Plug-in benötigt.

## Einrichtung

In der Tapo-App muss unter den erweiterten Kameraeinstellungen ein separates
Kamerakonto für Drittanbieter angelegt sein. Dieses Kamerakonto ist nicht das
TP-Link-/Tapo-Cloudkonto.

Camera Hub verwendet:

- RTSP/TCP auf Port `554`;
- `/stream1` als Hauptstream;
- `/stream2` als Substream;
- ONVIF Profile S auf Port `2020`;
- `/onvif/device_service` als Gerätedienst.

Die Kamerasuche prüft Port 2020 konservativ und kennzeichnet eine dort
gefundene ONVIF-Schnittstelle. Bei einem passenden Treffer werden die
Tapo-kompatiblen Stream-Pfade als bearbeitbare Vorschläge eingesetzt. Vor dem
Speichern muss Camera Hub echte Videopakete empfangen.

Zugangsdaten werden serverseitig mit AES-GCM verschlüsselt. Viewer-APIs und
Browsercode erhalten weder die Kameraadresse noch Benutzernamen, Kennwörter
oder authentifizierte RTSP-Adressen.

## Livebild und Funktionen

Die Übersicht und die WebRTC-Einzelansicht nutzen den Substream. Der
höher aufgelöste Hauptstream steht über den HLS-Schalter bereit.
Camera Hub prüft beide H.264-Profile auf B-Frames. WebRTC-kompatible Quellen
werden weiterhin unverändert übergeben. Enthält eine Quelle B-Frames, aktiviert
Camera Hub ausschließlich für diese Kamera einen H.264-Kompatibilitäts-Relay
mit Baseline-Profil, ohne Audio. Damit bleiben die vorhandenen direkten
Stream-Copy-Quellen unverändert und der Browser erhält für den Substream einen
stabil dekodierbaren WebRTC-Stream. Der Hauptstream wird für HLS auf
browserfreundliche 1080p normalisiert.

Beim getesteten Gerät meldete RTSP einen Session-Timeout von 15 Sekunden.
VLC/live555 empfing anschließend keine weiteren Pakete. Der
Kompatibilitätsweg verwendet daher einen ausschließlich im Compose-Netz
erreichbaren MediaMTX-Eingang, der die standardisierte RTSP-Sitzung aktiv
hält. FFmpeg liest nur diesen neutralen internen Pfad und erhält keine
Kamera-Zugangsdaten in seiner Befehlszeile. Weder der interne RTSP-Port noch
MediaMTX-Verwaltungsports werden am Host oder im LAN veröffentlicht.

Im lokalen Abnahmetest wurden echte Frames aus Haupt- und Substream
nachgewiesen. Der WebRTC-Substream blieb länger als 60 Sekunden live; der
HLS-Hauptstream wurde ebenfalls im Browser geöffnet. Ein ONVIF-PTZ-Befehl mit
anschließendem `Stop` wurde aus der geschützten Einzelansicht bestätigt.

Über ONVIF erkannte PTZ-Funktionen erscheinen nur für Eigentümer und
Administratoren. Camera Hub verwendet ausschließlich `ContinuousMove`, `Stop`
und – falls vorhanden – den Aufruf vorhandener Presets. Imaging-Einstellungen,
Kamerabenutzer, Netzwerk, Firmware und Aufzeichnung werden nicht verändert.

Die Tapo C220 stellt über ONVIF Profile S eine Audioquelle bereit.
Der aktuelle B-Frame-Kompatibilitäts-Relay arbeitet bewusst nur mit Video;
deshalb wird in der Liveansicht dafür noch kein Audio-Schalter angeboten.
Gegensprechen gehört nicht zum implementierten Funktionsumfang.

## Sicherheitsgrenzen

- RTSP- und ONVIF-Ports werden nicht ins Internet veröffentlicht.
- Fernzugriff erfolgt ausschließlich über das Camera-Hub-Gateway und VPN/HTTPS.
- Die Tapo-Cloud-Anmeldung wird nicht in Camera Hub gespeichert.
- Camera Hub verändert keine Kameraeinstellungen.
- Ein erfolgreicher Port- oder ONVIF-Test allein gilt nicht als
  Videonachweis; die Einrichtung verlangt empfangene Videopakete.

## Fehlerbehebung

Wenn ONVIF oder RTSP die Anmeldung ablehnt, ist zuerst zu prüfen, ob wirklich
das in der Tapo-App angelegte **Kamerakonto** verwendet wird. Bei ausbleibendem
Hauptstream sollte die Tapo-App geschlossen und anschließend erneut getestet
werden. Gleichzeitige Cloud-, SD-Karten- und Drittanbieter-Nutzung kann je nach
Kamerakonfiguration begrenzt sein.
