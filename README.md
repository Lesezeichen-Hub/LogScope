# LogScope 1.0.0

LogScope ist ein statisches, lokal arbeitendes Werkzeug zur Untersuchung von Logdateien. Die Oberfläche ist deutschsprachig; alle Dateien werden nur nach Benutzerauswahl gelesen. Der Produktionsbetrieb benötigt keinen Backenddienst und keine Internetverbindung.

## Start und Hub-Installation

Den Ordner mit `index.html`, `src/` und `version.json` auf einem statischen Webserver öffnen. Im Lesezeichen-Hub kann das Repository als Modul installiert werden; der Hub liefert die Datei unter `/modules/<id>/index.html` aus. Alle Ressourcenpfade sind relativ. Optional mit `npm run build` einen auslieferbaren `dist/`-Ordner erstellen. Node.js wird nur für Build und Tests verwendet. Die laufende Anwendung hat keine Drittbibliotheken.

## Bedienung

Dateien auswählen oder auf die Seite ziehen. In der Importvorschau Format, Kodierung, Syslog-Bezugsjahr und Zeitzonenoffset prüfen. Ohne explizite Zeitzone bleiben lokale Zeitstempel in der Timeline unvergleichbar. Mehrere Quellen können im Logviewer und in der Systemkorrelation zusammen betrachtet werden. Für einen Vorher/Nachher-Vergleich im Bereich „Vergleich“ die Quellen A und B zuordnen. Im Bereich „Berichte“ erst die Vorschau prüfen, dann Markdown, HTML, JSON oder CSV exportieren oder über den Browser als PDF drucken. Projekte werden nur über „Projekt speichern“ in IndexedDB abgelegt und über „Gespeichertes Projekt öffnen“ wiederhergestellt. Quellenmetadaten enthalten einen SHA-256-Fingerprint der ersten und letzten 64 KiB plus Dateigröße; dies ist keine Volltext-Prüfsumme.

## Formate und Grenzen

Erkannt werden Syslog, Journald JSON/Text, Caddy JSON/Konsole, MariaDB Error/Slow/General, Jenkins und generischer Text/JSONL. Weitere Parser lassen sich in `src/parser.js` anhand der `format`-Kennung ergänzen und in `src/core.js` registrieren. Binäre `.journal`-Dateien zuvor mit `journalctl --output=json` exportieren. Binäre MariaDB-Binlogs sind nicht unterstützt. `.gz` wird im Browser gestreamt und mit Grenzen für entpackte Größe und Verhältnis verarbeitet. `.zip` wird in der Vorschau abgewiesen; lokal entpacken und dann importieren. CSV wird als Text angezeigt. Die automatische Formatwahl nutzt eine Stichprobe; sie kann im Dialog überschrieben werden.

Der Worker liest Dateien inkrementell. Die normalisierten Ereignisse bleiben jedoch für die Sitzung im Arbeitsspeicher; bei 250.000 Ereignissen stoppt der Import und markiert die Quelle als unvollständig. Ein IndexedDB-Streamingimport und Virtualisierung aller Auswertungen sind noch nicht implementiert. Regex-Suche prüft die Ausdruckslänge, kann aber bei komplexen Mustern dennoch blockieren. Die aktuelle Version enthält keine frei definierbaren Parserprofile, keine grafische Filtersprache, keinen präzisen Text-Diff und keine Anomalieerkennung. HTTP-Latenzen setzen Caddys Standarddauer in Sekunden voraus. Mehrdeutige Sommerzeitstunden werden nicht aufgelöst; einen konkreten Offset angeben. Weder Zeitnähe noch Fingerprint-Gleichheit beweisen Kausalität.

## Datenschutz

Die Content-Security-Policy unterbindet Netzwerkanfragen. Importierte Texte werden als Text gerendert, nie ausgeführt. Berichte können IP-Adressen, E-Mail-Adressen und benannte Token-/Passwortfelder maskieren; diese Regeln erkennen nicht alle denkbaren Geheimnisse. Vor Weitergabe den Bericht prüfen. Gespeicherte Projekte enthalten Ereignis-Rohtext und gehören zur Browser-Origin; beim Wechsel von Host, Port oder Protokoll entsteht ein anderer Speicherbereich.

## Tests

`npm test` führt die parser- und analysebezogenen Node-Tests aus. Die Dateien unter `tests/fixtures/` sind synthetisch. `npm run test:browser` führt einen Browser-Smoke-Test für Import, Gzip, Vergleich und Projektwiederherstellung unter `/modules/demo/index.html` aus. Dafür ist Playwright samt Browser lokal erforderlich; alternativ können `LOGSCOPE_PLAYWRIGHT_ROOT`, `LOGSCOPE_BROWSER_PATH` und `LOGSCOPE_STATIC_ROOT=dist` gesetzt werden. Performance-Benchmarks sind noch nicht vorhanden; es werden keine Leistungswerte behauptet.
