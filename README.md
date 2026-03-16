# Lokale Pwned-Checker-Anwendung

Diese Anwendung bietet eine lokale Weboberfläche zur Überprüfung von
Passwörtern auf bekannte Sicherheitsvorfälle. Sie läuft lokal auf Ihrem
Rechner: Passwörter werden niemals im Klartext übertragen oder
gespeichert. Statt jede Prüfung rein online auszuführen, hält die App
einen lokalen Cache der benötigten Pwned-Passwords-Hashbereiche vor und
kann diesen aus der Weboberfläche aktualisieren.

## Architekturüberblick

Die Anwendung ist in Python mit [FastAPI](https://fastapi.tiangolo.com/)
umgesetzt und folgt einer modularen Struktur:

* **main.py**: Startpunkt der Webapp, definiert Routen und Oberfläche.
* **services/**: Enthält Module für CSV-Parsing, Passwort-Hashing,
  lokalen Prefix-Cache, Schwachstellenbewertung und Reuse-Erkennung.
* **templates/**: Jinja2-Templates für die HTML-Oberfläche.
* **static/**: Statische Ressourcen wie CSS.
* **tests/**: Automatisierte Tests für Kernfunktionalität.

Die App nutzt das [k-Anonymity-Verfahren](https://haveibeenpwned.com/API/v3#PwnedPasswords)
der Pwned Passwords API, um nur die benötigten SHA-1-Präfixe lokal
zwischenzuspeichern. Danach können bereits geladene Bereiche offline
ausgewertet werden.

## Verzeichnisstruktur

```text
pwned_checker_app/
├── __init__.py
├── main.py
├── requirements.txt
├── README.md
├── services/
│   ├── __init__.py
│   ├── csv_parser.py
│   ├── password_analysis.py
│   ├── pwned_cache.py
│   └── pwned_passwords.py
├── static/
│   └── styles.css
├── templates/
│   ├── base.html
│   └── index.html
└── tests/
    ├── test_csv_parser.py
    ├── test_password_analysis.py
    ├── test_pwned_cache.py
    ├── test_pwned_passwords.py
    └── test_report_generation.py
```

## Einrichtung und Installation

1. **Python-Umgebung erstellen**

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. **Abhängigkeiten installieren**

   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. **Keine API-Keys notwendig**

   Die Anwendung benötigt keinen API-Key. Beim ersten Check eines neuen
   Passwort-Hash-Präfixes wird der passende Bereich lokal
   zwischengespeichert. Bereits geladene Bereiche können später aus der
   Weboberfläche erneut aktualisiert werden.

## Start der Anwendung

Starten Sie die Anwendung aus dem Projektverzeichnis:

```bash
python main.py
```

Alternativ können Sie sie aus dem Elternverzeichnis mit Uvicorn starten:

```bash
uvicorn pwned_checker_app.main:app --host 127.0.0.1 --port 8000
```

Öffnen Sie anschließend `http://127.0.0.1:8000`.

## Sicherheitshinweise und Grenzen

* **Lokale Verarbeitung**: Die Anwendung bindet an `127.0.0.1` und
  speichert keine Passwörter oder CSV-Dateien dauerhaft. Hochgeladene
  Daten verbleiben im Arbeitsspeicher und werden nach der Analyse
  verworfen.
* **Lokaler Hash-Cache**: Es wird nur der Präfix (die ersten fünf
  Zeichen) des SHA-1-Hashes an den Pwned-Passwords-Dienst gesendet, wenn
  ein Bereich noch nicht lokal vorhanden ist oder manuell aktualisiert
  wird. Der vollständige Hash verbleibt lokal.
* **Rate Limiting**: Beim Laden mehrerer Präfixe wird eine kurze Pause
  zwischen den Anfragen eingelegt, um den Dienst nicht unnötig zu
  belasten.
* **CSRF-Schutz**: Obwohl die App lokal läuft, wird ein einfacher
  CSRF-Token eingesetzt, um ungewollte POST-Anfragen zu verhindern.
* **Export**: Der exportierte Report enthält keine Passwörter. Er
  umfasst nur Website, Benutzername, Anzahl der Kompromittierungen,
  Wiederverwendung und Hinweise auf schwache Passwörter.

## Weiterführende Informationen

Weitere Details zur Funktionsweise der Pwned Passwords API finden Sie in
der offiziellen Dokumentation:
https://haveibeenpwned.com/API/v3#PwnedPasswords
