# LogScope 1.2.0

LogScope ist ein statisches, lokal arbeitendes Werkzeug zur Untersuchung von Logdateien. Die Oberfläche ist deutschsprachig; alle Dateien werden nur nach Benutzerauswahl gelesen. Der Produktionsbetrieb benötigt keinen Backenddienst und keine Internetverbindung.

## Start und Hub-Installation

Den Ordner mit `index.html`, `src/` und `version.json` auf einem statischen Webserver öffnen. Im Lesezeichen-Hub kann das Repository als Modul installiert werden; der Hub liefert die Datei unter `/modules/<id>/index.html` aus. Alle Ressourcenpfade sind relativ. Optional mit `npm run build` einen auslieferbaren `dist/`-Ordner erstellen. Node.js wird nur für Build und Tests verwendet. Die laufende Anwendung hat keine Drittbibliotheken.

## Bedienung

Dateien auswählen oder auf die Seite ziehen. In der Importvorschau Format, Kodierung, Syslog-Bezugsjahr und Zeitzonenoffset prüfen. Ohne explizite Zeitzone bleiben lokale Zeitstempel in der Timeline unvergleichbar. Mehrere Quellen können im Logviewer und in der Systemkorrelation zusammen betrachtet werden. Für einen Vorher/Nachher-Vergleich im Bereich „Vergleich“ die Quellen A und B zuordnen. Im Bereich „Berichte“ erst die Vorschau prüfen, dann Markdown, HTML, JSON oder CSV exportieren oder über den Browser als PDF drucken. Projekte werden nur über „Projekt speichern“ in IndexedDB abgelegt und über „Gespeichertes Projekt öffnen“ wiederhergestellt. Quellenmetadaten enthalten einen SHA-256-Fingerprint der ersten und letzten 64 KiB plus Dateigröße; dies ist keine Volltext-Prüfsumme.

## Formate und Grenzen

Der Logviewer zeigt auch Einträge ohne Zeitstempel. Bei neuen Importen werden bestehende Such- und Zeitfilter zurückgesetzt; im Logviewer zeigt ein Zähler die sichtbaren und insgesamt geladenen Ereignisse. Die Timeline bietet alle in den Dateien vorhandenen Jahre zur Auswahl und zeigt den ersten und letzten Zeitpunkt sowie die Anzahl datierter und undatierter Ereignisse je Datei. Führende ISO-Zeitstempel werden auch bei generischem Text erkannt. Für Syslog ohne Jahr und lokale Zeitstempel ohne Zeitzone müssen Bezugsjahr und Offset bereits beim Import angegeben werden. Twisted-Logs wie `CRITICAL:twisted:Unhandled Error` werden mitsamt Traceback als Ereignis angezeigt. Fehlt im Log ein Datum, erscheint es nicht in der Timeline; LogScope erfindet dafür keinen Zeitpunkt.

Erkannt werden Syslog, Journald JSON/Text, Caddy JSON/Konsole, MariaDB Error/Slow/General, Jenkins und generischer Text/JSONL. Zusätzlich sind folgende Parser vorhanden:

| Bereich | Unterstützte Formate |
| --- | --- |
| Web | Apache/Nginx Common und Combined Access, Apache/Nginx Error |
| Datenbanken | MySQL Error (Text und JSON), Slow und General Query; MongoDB Structured JSON und älteres Textformat; Db2 `db2diag.log`; PostgreSQL stderr, JSON und CSV |
| AWS | CloudTrail Records und JSONL, CloudWatch `logEvents` und JSONL, ALB Access, VPC Flow Logs im Standardformat, WAF JSON, S3 Server Access, CloudFront Standard Access, ECS/FireLens JSON, Lambda Text/JSON |
| Kubernetes | CRI-Containerlogs mit `P`/`F`-Fragmenten, klog-Text, Docker JSON, Audit JSON, Event JSON und `EventList` |

Bei MySQL und MariaDB sind Slow- und General-Logs anhand des Inhalts häufig nicht unterscheidbar. Ein Dateiname mit `mysql` dient als zusätzlicher Hinweis; in der Importvorschau kann das Format manuell korrigiert werden. CloudWatch-Einzelereignisse ohne AWS-Metadaten können wie generisches JSONL aussehen; auch hier das Format bei Bedarf überschreiben. `aws-vpc` verarbeitet die Standardspalten der Version 2; benutzerdefinierte Spaltenreihenfolgen werden nicht automatisch interpretiert. Die Access-Parser erwarten Common/Combined-Layouts. Kubernetes-Podmetadaten werden nur dann aus dem Dateinamen übernommen, wenn dieser dem üblichen Containerlog-Schema entspricht. Klog-Zeitstempel benötigen ein Bezugsjahr und einen Zeitzonenoffset. HTTP-Status, WAF-Aktion, VPC-Aktion und Container-Stream sind eigene Felder und kein automatisch abgeleiteter Log-Schweregrad.

Weitere Parser lassen sich in `src/extended-parsers.js` registrieren; `src/parser.js` übernimmt das normalisierte Ereignismodell und `src/worker.js` den Stream-Import. Formatangaben beruhen auf den Dokumentationen von [MongoDB](https://www.mongodb.com/docs/manual/reference/log-messages/), [MySQL](https://dev.mysql.com/doc/refman/8.4/en/error-log-format.html), [Db2](https://www.ibm.com/docs/en/db2/11.5.x?topic=files-interpreting-diagnostic-log-file-entries), [PostgreSQL](https://www.postgresql.org/docs/18/runtime-config-logging.html), [AWS ALB](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html), [AWS VPC](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html), [AWS CloudFront](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/standard-logs-reference.html), [AWS S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/LogFormat.html) und [Kubernetes CRI](https://github.com/kubernetes/design-proposals-archive/blob/main/node/kubelet-cri-logging.md).

Binäre `.journal`-Dateien zuvor mit `journalctl --output=json` exportieren. Binäre MariaDB-Binlogs sind nicht unterstützt. `.gz` wird im Browser gestreamt und mit Grenzen für entpackte Größe und Verhältnis verarbeitet. `.zip` wird in der Vorschau abgewiesen; lokal entpacken und dann importieren. Andere CSV-Layouts als PostgreSQL-CSV werden als Text angezeigt. Die automatische Formatwahl nutzt eine Stichprobe; sie kann im Dialog überschrieben werden.

Der Worker liest Dateien inkrementell. Die normalisierten Ereignisse bleiben jedoch für die Sitzung im Arbeitsspeicher; bei 250.000 Ereignissen stoppt der Import und markiert die Quelle als unvollständig. Ein IndexedDB-Streamingimport und Virtualisierung aller Auswertungen sind noch nicht implementiert. Regex-Suche prüft die Ausdruckslänge, kann aber bei komplexen Mustern dennoch blockieren. Die aktuelle Version enthält keine frei definierbaren Parserprofile, keine grafische Filtersprache, keinen präzisen Text-Diff und keine Anomalieerkennung. HTTP-Latenzen setzen Caddys Standarddauer in Sekunden voraus. Mehrdeutige Sommerzeitstunden werden nicht aufgelöst; einen konkreten Offset angeben. Weder Zeitnähe noch Fingerprint-Gleichheit beweisen Kausalität.

## Datenschutz

Die Content-Security-Policy unterbindet Netzwerkanfragen. Importierte Texte werden als Text gerendert, nie ausgeführt. Berichte können IP-Adressen, E-Mail-Adressen und benannte Token-/Passwortfelder maskieren; diese Regeln erkennen nicht alle denkbaren Geheimnisse. Vor Weitergabe den Bericht prüfen. Gespeicherte Projekte enthalten Ereignis-Rohtext und gehören zur Browser-Origin; beim Wechsel von Host, Port oder Protokoll entsteht ein anderer Speicherbereich.

## Tests

`npm test` führt die parser- und analysebezogenen Node-Tests aus. Die Dateien unter `tests/fixtures/` sind synthetisch. `npm run test:browser` prüft Import, Gzip, Vergleich und Projektwiederherstellung; `npm run test:browser:extended` importiert Web-, MongoDB-, Db2-, AWS- und Kubernetes-Beispiele; `npm run test:browser:timeline` prüft Logviewer und Timeline mit 5.300 synthetischen Ereignissen. Die Browser-Tests laufen unter `/modules/demo/index.html`. Dafür ist Playwright samt Browser lokal erforderlich; alternativ können `LOGSCOPE_PLAYWRIGHT_ROOT`, `LOGSCOPE_BROWSER_PATH` und `LOGSCOPE_STATIC_ROOT=dist` gesetzt werden. Performance-Benchmarks sind noch nicht vorhanden; es werden keine Leistungswerte behauptet.
