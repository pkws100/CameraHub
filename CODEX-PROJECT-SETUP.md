# Codex-Projekt für PKWS Camera Hub einrichten

## Empfohlener Projekttyp

Für Camera Hub ist ein **lokales Codex-Projekt** richtig. Damit erhält Codex
direkten, kontrollierten Zugriff auf den Git-Checkout, während GitHub weiterhin
Remote, CI-, Pull-Request- und Releaseplattform bleibt.

Primärer Projektordner:

```text
C:\Users\webma\Documents\CameraHub\auftrag-czeview-5-mp-solar-akkukamera\work\CameraHub
```

Nicht den darüberliegenden Auftragsordner als primär setzen: Automatische
Erkennung von `AGENTS.md`, `.codex/config.toml` und Git-Aktionen richtet sich
nach dem primären Ordner.

## Einrichtung in der Codex-/ChatGPT-Desktop-App

1. In der App die Ansicht **Projects/Projekte** öffnen.
2. Ein neues lokales Projekt mit dem Namen **PKWS Camera Hub** anlegen.
3. Im Projektmenü **Edit project/Projekt bearbeiten** wählen.
4. Über **Add folder/Ordner hinzufügen** den oben genannten Repository-Ordner
   hinzufügen.
5. Diesen Ordner über **Make primary/Als primär festlegen** zum primären Ordner
   machen.
6. Das Repository als vertrauenswürdig bestätigen, damit die projektbezogene
   `.codex/config.toml` geladen werden darf.
7. Den GitHub-Connector beziehungsweise die vorhandene `gh`-Anmeldung für
   `pkws100/CameraHub` verbunden lassen.
8. Einen neuen Chat **Camera Hub – Bestandsaufnahme** starten und den Inhalt
   aus `CODEX-PROJECT-PROMPT.md` einfügen.

Für jedes größere Ziel einen eigenen Chat verwenden, zum Beispiel:

- Release und Migration
- Kamera-/Cloudintegration
- Stream- und Browserregression
- Sicherheit und Code Review
- Betrieb und Deployment

Dadurch bleibt jeder Chat fokussiert; `AGENTS.md` liefert trotzdem automatisch
dieselben dauerhaften Projektregeln.

## Bereits vorbereitete Projektdateien

- `AGENTS.md`: automatisch geladene Architektur-, Sicherheits-, Test- und
  Reviewregeln.
- `.codex/config.toml`: sichere Projektdefaults; Secrets werden aus der
  Shellumgebung herausgefiltert.
- `CODEX-PROJECT-PROMPT.md`: vollständiger Start-Prompt für den ersten Chat.
- Diese Datei: Einrichtungs- und Nutzungsanleitung.

## GitHub-Ausgangslage vom 3. August 2026

Diese Angaben dienen nur als Übergabepunkt und müssen in jedem neuen Chat neu
verifiziert werden:

- GitHub-Repository: `pkws100/CameraHub`.
- Stabiler Remote-Branch: `main` bei Commit `51d1ebd`.
- Draft-PR #13: Alarmzonenerkennung 1.5.0 gegen `main`, CI erfolgreich.
- Draft-PR #14: Blink-Integration 1.6.0 gegen den Branch von PR #13, CI
  erfolgreich.
- Lokaler Arbeitsbranch bei Erstellung dieser Anleitung:
  `agent/blink-cloud-integration` bei Commit `73921e8`.

## Optionale lokale Umgebung und Aktionen

Die Desktop-App kann unter den Codex-Projekteinstellungen eine lokale Umgebung
mit Setupskript und häufigen Aktionen erzeugen. Sinnvolle Aktionen sind:

- **Status**: `./status-zmodo-pwa.ps1`
- **Start HTTP**: `./start-zmodo-pwa.ps1 -Mode HttpTest -LanAddress <private IPv4-Adresse>`
- **Stopp**: `./stop-zmodo-pwa.ps1`
- **Browsertests**: `npm run test:e2e`
- **Git-Status**: `git status -sb`

Die lokale Umgebung sollte über die App erzeugt werden, damit ihr jeweils
aktuelles Dateiformat verwendet wird. In Setupskripten keine `.env`-Dateien,
Secrets oder reale Zugangsdaten erzeugen oder einchecken.

## Verifikation

Nach dem Anlegen einen neuen Chat starten und Codex fragen:

```text
Nenne die geladenen Projektanweisungen, den primären Arbeitsordner, den
aktuellen Git-Branch und die ersten fünf unveränderlichen Camera-Hub-Regeln.
Nimm keine Änderungen vor.
```

Die Antwort muss `AGENTS.md`, den CameraHub-Repository-Ordner und den aktuellen
Branch erkennen. Wenn nicht, das Projektmenü öffnen und kontrollieren, ob der
CameraHub-Ordner wirklich als primärer Ordner eingestellt ist.
