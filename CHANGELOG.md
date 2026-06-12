# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.3.1] - 2026-06-12

### Fixed
- Webhooks-Seite: Beschreibungstext der "Payload Format"-Karte korrigiert — die Aussage "Every delivery is an HTTP POST with Content-Type: application/json" galt seit 1.3.0 nicht mehr (Methode, Header und Body-Format sind pro Webhook konfigurierbar)
- Payload-Beispiel zeigt jetzt die tatsächliche Anwendungsversion (dynamisch via `Version::current()`) statt einer hartcodierten Versionsnummer
- Quick Presets ersetzen jetzt auch eine bereits eingetragene Endpoint-URL (vorher wurde die URL nur in ein leeres Feld übernommen); das Generic-JSON-Preset lässt die URL unverändert

## [1.3.0] - 2026-06-12

### Added
- Flexible Webhook-Delivery: HTTP-Methode (POST/PUT/PATCH/GET), eigene HTTP-Header (z. B. API-Keys) und Body-Format pro Webhook konfigurierbar — `json` (strukturiertes Payload), `form` (x-www-form-urlencoded) oder `custom` (frei definierbares Body-Template)
- Template-Platzhalter für Body und URL: `{{ip}}`, `{{categories}}`, `{{abuseipdb_categories}}`, `{{comment}}`, `{{severity}}`, `{{analyzers}}`, `{{uri}}`, `{{method}}`, `{{user_agent}}`, `{{host}}`, `{{timestamp}}`, `{{version}}`, `{{event}}` — jeweils auch als `_url`- (URL-encoded) und `_json`-Variante (JSON-escaped)
- AbuseIPDB-Unterstützung: `{{abuseipdb_categories}}` mappt reportedip.de-Kategorien automatisch auf AbuseIPDB-IDs (1–23 identisch, CMS-Kategorien 24–58 auf nächstliegende Äquivalente)
- Quick-Presets im Admin-Formular: AbuseIPDB, Slack, Discord, Generic JSON
- Test-Deliveries nutzen die Loopback-IP 127.0.0.1, damit externe Abuse-Datenbanken Testreports ablehnen statt sie zu speichern
- Schema-Migration: neue Spalten `method`, `headers`, `body_format`, `body_template` in `honeypot_webhooks` (automatisch via `ensureColumns`)
- 11 neue Tests (Kategorie-Mapping, Template-Rendering, Header-Parsing, Feld-Aggregation)

## [1.2.1] - 2026-06-12

### Fixed
- HTTP 500 auf `/_hp_admin/webhooks` bei Installationen mit veraltetem Composer-Autoloader: `vendor/` ist beim Self-Update ein geschützter Pfad — eine dort liegende optimierte Classmap vom Stand vor 1.2.0 kennt die neuen Klassen (`WebhookRepository`, `WebhookDispatcher`, `Version`) nicht und lieferte "Class not found". Der PSR-4-Fallback-Autoloader in `public/index.php` und `cli.php` wird jetzt immer registriert, auch wenn `vendor/autoload.php` existiert
- `UpdateManager`: nach dem Dateitausch werden `clearstatcache()` und `opcache_reset()` ausgeführt, damit ersetzte Dateien sofort wirken und kein Mix aus altem und neuem Code entsteht

## [1.2.0] - 2026-06-12

### Added
- Webhooks: Detections können in Echtzeit an eigene Logging-/SIEM-Systeme weitergeleitet werden — neuer Admin-Menüpunkt "Webhooks" mit Verwaltung externer Report-Ziele (JSON-POST, Filter nach Kategorien und/oder Analyzern mit ODER-Logik, optionale HMAC-SHA256-Signatur via `X-ReportedIP-Signature`, Test-Button, Zustellstatus und Fehlerzähler pro Webhook)
- Neue SQLite-Tabelle `honeypot_webhooks` (automatische Migration via `Database::initialize()`)
- Webhook-Zustellung erfolgt nach dem Senden der Trap-Response — keine Verzögerung für den Angreifer
- Zentrale `Version`-Klasse: API-Kommunikation Richtung reportedip.de sendet jetzt immer die aktuelle Version aus der `VERSION`-Datei (dynamischer `User-Agent` statt hartcodiert `1.0.0`, zusätzlich neuer Header `X-Honeypot-Version`)
- 22 neue Tests (WebhookRepository, WebhookDispatcher, Versions-Header) plus E2E-Test-Skripte (`tests/e2e-webhook-*.php`)

### Fixed
- IpResolver: Cloudflare-IPv6-Ranges (u. a. `2a06:98c0::/29`, `2606:4700::/32`) ergänzt — bisher wurde hinter Cloudflare bei IPv6-Origin-Verbindungen die Edge-IP statt der echten Client-IP aus `CF-Connecting-IP` gemeldet (API lehnte mit `ip_whitelisted` ab)
- HeaderAnomalyAnalyzer: False Positive "Suspicious X-Forwarded-For with loopback address" bei legitimen IPv6-Adressen behoben — `::1` wurde als ungeankerter Substring gematcht (z. B. in `2a06:98c0:3600::103`); Loopback-Erkennung vergleicht jetzt jeden XFF-Eintrag exakt
- ReportQueue: permanent von der API abgelehnte Reports (HTTP 4xx außer 429, z. B. whitelisted IPs) werden als `sent = 2` aus der Queue genommen statt endlos retried — verhinderte bisher per Head-of-line-Blocking das Senden neuer Reports
- `config.example.php` und WebInstaller: Cloudflare-IPv6-Ranges in `trusted_proxies`-Default aufgenommen

## [1.1.0] - 2026-02-27

### Added
- Self-update system: automatic version checks via GitHub Releases API every 3 hours (web cron)
- Admin panel "Updates" tab with version status, release notes, system checks, update history, and backup management
- Auto-update toggle (enabled by default) with manual "Check Now" and "Update Now" buttons
- CLI commands: `check-update` (query GitHub for new versions) and `update` / `update --rollback`
- Automatic backup before each update with rollback on failure (max 3 backups retained)
- Protected paths: `config/config.php`, `data/`, and `vendor/` are never overwritten during updates
- VERSION file for tracking the current application version
- App version displayed in admin dashboard System Information section
- Update notification badge in admin sidebar when a new version is available
- Config options: `auto_update` (bool) and `update_check_interval` (seconds)
- 11 new tests for UpdateChecker and UpdateManager (325 total)

### Security
- Download URLs validated: HTTPS only, GitHub domains only
- Lock mechanism with 10-minute stale timeout prevents concurrent updates
- Sanity check: extracted archive must contain `src/Core/App.php`, `VERSION`, `public/index.php`
- All admin update actions protected by CSRF tokens
- Backup name input sanitized against path traversal

## [1.0.0] - 2026-02-26

### Added
- CMS emulation: WordPress, Drupal, and Joomla profiles with realistic URL patterns, headers, and templates
- 36 threat analyzers: SQL injection, XSS, path traversal, brute force, credential stuffing, SSRF, XML-RPC abuse, plugin exploits, config file access, vulnerability probes, user agent analysis, header anomalies, HTTP verb abuse, path scanning, form spam, theme exploits, user enumeration, file upload malware, admin directory scanning, resource exhaustion, WP-Cron abuse, version fingerprinting, database backup access, registration honeypot, search spam, trackback/pingback spam, media library abuse, WP-CLI abuse, core file modification, AJAX endpoint abuse, open redirect, password reset abuse, session hijacking, Unicode encoding attacks, rate limit bypass, JavaScript injection
- Automatic API reporting to reportedip.de with queue-based batch processing, rate limiting, and exponential backoff
- Admin dashboard with statistics, activity charts, filterable attack logs, whitelist management, and visitor tracking
- AI content generation via OpenAI API (AJAX-based, post by post) for realistic fake CMS content
- Bot detection and visitor classification (good bots, bad bots, AI agents, hackers, humans)
- Cloudflare and reverse proxy support via configurable trusted_proxies
- Docker support with Dockerfile, docker-compose, nginx, and php-fpm configurations
- CLI tools: stats, process-queue, cleanup, whitelist management, API connectivity test
- Security hardening: CSRF protection, bcrypt authentication, brute-force lockout, security headers (CSP, X-Frame-Options, HSTS), session IP binding, SameSite cookies
- Interactive install wizard (`install.php`) with PHP checks, config generation, and database setup
- Custom lightweight test framework with 311+ tests
- SQLite persistence with WAL mode, auto-schema creation
- Built-in PSR-4 autoloader (no Composer required)
