# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.4.0] - 2026-09-15

### Added
- **Whitelist mirroring from the API** (#6) — when the API rejects a report because the IP is on its own whitelist (HTTP 400, `ip_whitelisted` — verified search-engine crawlers and the like), the honeypot now copies that verdict into the local whitelist for 7 days, described as `Auto: <category>: <reason> (reportedip.com)`. Those requests are no longer detected, queued or sent at all, instead of producing a rejected report on every hit. `honeypot_whitelist` gained an `expires_at` column (added in place on existing installations); entries added by hand stay permanent and mirroring never time-limits them. Expired entries are dropped by the regular cleanup in both queue modes, and `whitelist-list` plus the admin panel show the expiry.
- **Clickable summary cards in the visitor log** (#5) — the five counters above the log now filter it by visitor type. They keep the bot-name and IP filters that are already active, reset pagination, mark the active card, and clear the filter again when it is clicked a second time. The cards also state that their counts cover the last 24 hours, while the log below covers the full retention period.

### Fixed
- **"Wordpress" misspelled across the admin panel** (#2) — the CMS profile identifier is lowercase and every label ran it through `ucfirst()`, rendering "Wordpress". Labels now resolve through `CmsProfile::displayName()`, which maps identifiers to their official names (WordPress, Drupal, Joomla). Affects the dashboard system info and empty state, the content list and generator headers, and the CMS name handed to the content-generation prompt.
- **Visitor-type labels** — derived from the identifier, they rendered as "Ai agent" in the filter dropdown and fully lowercase on the cards. Cards, dropdown and table badges now share one label list (`VisitorLogger::TYPE_LABELS`).

## [1.3.12] - 2026-09-11

### Fixed
- **False positive on `/robots.txt` and `/sitemap.xml`** — `PathScanningAnalyzer` no longer treats standard requests to `/robots.txt` or `/sitemap.xml` as a reconnaissance attack (previously reporting categories 14: Port Scan + 15: Hacking). This prevents false abuse reports when unlisted crawlers, browsers, or search bots fetch robots/sitemap files. Harvesting detection is still cleanly handled by `SpiderTrapAnalyzer` when a bot requests the hidden bait path advertised inside those files.

### Added
- **Expanded AI and search bot classification in `BotDetector`** — added recognition for modern AI search and retrieval agents including `OAI-SearchBot` (OpenAI SearchBot), `Claude-User`, `Claude-SearchBot`, `Perplexity-User`, `Amazonbot`, `Amzn-SearchBot`, `Amzn-User`, `Google-CloudVertexBot`, `Meta-ExternalFetcher`, `MistralBot`, `DeepSeek`, `YouBot`, `DuckAssistBot`, and `Timpibot`.
- **Expanded search engine and preview crawlers** — added `GoogleOther`, `Google-InspectionTool`, `Storebot-Google`, `Google-Read-Aloud`, `Google-Site-Verification`, `BingPreview`, `msnbot`, `archive.org_bot`, `ia_archiver`, `Qwantify`, `Sogou`, `MojeekBot`, `SeznamBot`, `Pinterestbot`, `Slackbot`, `Discordbot`, `TelegramBot`, and `WhatsApp`.
- **Additional HTTP client library patterns** — added `aiohttp`, `httpx`, `reqwest`, `Postman`, and `Guzzle` to automated bot classification.
- **Unit & E2E test suites** — added `BotDetectorTest` unit test suite and `tests/e2e-docker-test.php` for automated end-to-end testing against Docker honeypot instances.

## [1.3.11] - 2026-09-06

### Added
- **Gravity SMTP credential-disclosure sensor** — `PluginExploitAnalyzer` now detects probes against `gravitysmtp/v1/tests/mock-data`, the unauthenticated Gravity SMTP endpoint that leaks stored SMTP/API provider credentials. A fleet rollout showed 259 such requests from 17 IPs going undetected because the probe also arrives as `?rest_route=/gravitysmtp/v1/...` where the request path is just `/` — the analyzer's leading `/` guard skipped it. The check now runs before that guard and matches both the `/wp-json/gravitysmtp/v1/` and `rest_route` forms, reporting categories 35 (Plugin Exploit) + 57 (Plugin Scanning) + 58 (Config Exposure); the `mock-data` credential endpoint scores higher (80) than a generic plugin probe (65).
- **IoT/appliance visitor-API probe** added to `foreignFrameworkPaths()` — `/open/visitors/info/…` (seen 84 times fleet-wide, previously unlogged), flagged by `ForeignFrameworkProbeAnalyzer` as an indiscriminate scan (category 61).

### Notes
- Log-vs-detection audit across the 21-host fleet confirmed full sensor coverage over HTTPS. The remaining log-only requests are plain-HTTP (port 80) hits that the web server 301-redirects to HTTPS before they reach the honeypot; capturing those requires unchecking "Rewrite HTTP to HTTPS" in the site's web-server config and is outside this repository.

## [1.3.10] - 2026-09-05

### Added
- **New sensor: `RestBatchExploitAnalyzer` (wp2shell / CVE-2026-63030)** — detects exploitation of the WordPress REST batch endpoint (`/wp-json/batch/v1`, `?rest_route=/batch/v1`), the unauthenticated pre-auth RCE chain that was hitting the live honeypot as `POST /?rest_route=/batch/v1&_w2s=…` but was only ever logged as a generic hacker visit. The analyzer flags the `_w2s` campaign marker, rogue-admin/webshell naming (`w2s_`/`wp2_`), nested-batch route confusion, and the SQL-injection primitive (including `INTO OUTFILE` webshell drops). Reports categories 34 (REST API Abuse) + 37 (Core Exploit), escalating to 45 (DB Injection) and 46 (Backdoor Installation) when those signatures appear. Pipeline is now 40 analyzers.
- **Three mass-install plugins added to the fake plugin registry**, each advertising a version vulnerable to a widely exploited CVE, so scanners fingerprinting the `readme.txt` Stable tag keep engaging: `litespeed-cache` (CVE-2024-28000, 6M+ installs), `w3-total-cache` (CVE-2025-9501 RCE, 1M+), `wpvivid-backuprestore` (CVE-2026-1357 unauthenticated upload-to-RCE, 900k). Registry is now 20 plugins.

## [1.3.9] - 2026-09-05

### Added
- **Seven high-profile plugins added to the fake plugin registry**, each advertising a version that is vulnerable to a widely exploited 2026 CVE. Mass-scanning campaigns fingerprint installed plugins by fetching `/wp-content/plugins/<slug>/readme.txt` and reading the `Stable tag`; the honeypot now returns a convincing readme for exactly the slugs and versions those campaigns hunt for, so a scanner flags the site as exploitable and proceeds to its actual exploit request (which the detection pipeline logs and reports). New entries: `kirki` (CVE-2026-8206, account takeover), `burst-statistics` (CVE-2026-8181, REST auth bypass), `translatepress-multilingual` (CVE-2026-19632, reset-key disclosure), `pods` (CVE-2026-19598, privilege escalation), `give` (CVE-2026-82222, PHP object injection), `everest-forms` (CVE-2026-3300, unauthenticated RCE), `breeze` (CVE-2026-3844, SSRF). No routing or trap code changed — the readme/asset/directory handling in `FakeVulnTrap` already resolves any registered slug generically via `WordPressPluginRegistry::hasPlugin()`.

## [1.3.8] - 2026-08-31

### Removed
- **Dead code sweep (~590 lines)** following a repo-wide over-engineering audit; no functional changes:
  - `Core\Cache` and its test — the file-based TTL cache was never instantiated anywhere
  - `App::serveTrapFallback()` and `fallbackLoginPage()` — an unreachable template-rendering fallback for the case that trap classes "are not available"; all traps ship in this repository
  - `CmsProfile::getAdminPath()` / `getApiPaths()` abstract methods and their three implementations — declared but never called
  - `ProfileFactory` — single caller; the profile match now lives directly in `App::loadProfile()`
  - `Request::toArray()` and `Config::has()` — only referenced by their own tests
  - Unused config keys `cache_path`, `cache_ttl`, `debug`, `session_lifetime`, `log_human_visitors` (written by the installer, read by nothing; existing configs keep working — unknown keys are simply ignored)
  - `data/cache/` directory scaffolding (`.gitkeep`, Dockerfile `mkdir`, ignore entries)

### Changed
- `Router::route()` now emits the registered trap names directly (`fake_vuln`, `rest_api`, `registration`, ...) instead of intermediate names that `App::serveTrap()` re-mapped a second time; the unreachable honeypot-admin branch in `route()` is gone (the admin panel is intercepted via `isAdminPath()` before routing, as before)
- `App::registerTraps()` and `App::handleAdmin()` instantiate their classes directly instead of going through string class names with `class_exists()` guards
- CSRF token lifetime is now tied to `AdminAuth::SESSION_LIFETIME` (single source) instead of the half-wired `session_lifetime` config key
- Admin dashboard reads the app version via `Version::current()` instead of re-reading the `VERSION` file by hand

## [1.3.7] - 2026-08-30

### Fixed
- **Reports were silently dropped when they carried a honeypot category**: the high-interaction categories 59-63 (honeytoken, webshell, indiscriminate scan, source disclosure, spider trap), introduced in 1.3.3, did not exist in the reportedip.com catalogue. The API validates every reported ID against its own table and rejects the WHOLE report with HTTP 400 (`rest_invalid_param: Invalid parameter(s): categories`) as soon as one ID is unknown — so a detection such as `14,15,19,21,49,61` was refused in full, and because `ReportQueue` treats 4xx as final, the entry was discarded instead of retried. The API now knows 59-63; `ReportClient` additionally retries such a rejection ONCE with only the categories every deployment accepts (`stripUnsupportedCategories()`), so a client running ahead of its API loses categories instead of the whole report
- **Category registry no longer drifts from the API catalogue**: `CategoryRegistry` carried its own names and severities for IDs 22-58, which diverged from what reportedip.com actually files under those IDs (e.g. 25 was "Data Harvesting" locally but "Ransomware C&C" upstream, 28 "Backdoor Access" vs. "Supply Chain Attack", 47 "Directory Traversal" vs. "WP SEO Spam"). The admin panel therefore showed one threat while the platform recorded another. Names and severity levels now mirror `GET /wp-json/reportedip/v2/categories`, and the new `CategoryRegistryTest` pins the table to that catalogue
- **Three analyzers reported the wrong threat upstream** as a consequence of that drift: `SpiderTrapAnalyzer` sent 25, filed as *Ransomware C&C* (severity 10) for what is a bait-path fetch — now 48 *WP Content Scraping*; `WebshellAccessAnalyzer` sent 28/30, filed as *Supply Chain Attack* / *Nation State* — now 46 *WP Backdoor Installation* + 43 *WP File Upload Malware*; `Honeytoken` sent 28 — now 46. `UserAgentAnalyzer` no longer claims 49 *WP Fake SEO Bot* for any suspicious client string and reports 19 *Bad Web Bot* alone

### Changed
- AbuseIPDB webhook mapping realigned to the corrected category meanings and extended to 59-63 (previously they fell through to the catch-all *Web App Attack*): 45 now maps to *SQL Injection* + *Web App Attack*, 39 to *Blog Spam*, 47 to *Web Spam*, 25/26/27 to *Exploited Host*, 59 to *Hacking* + *Brute-Force*, 61 to *Port Scan* + *Web App Attack*, 63 to *Bad Web Bot*

## [1.3.6] - 2026-08-06

### Changed
- **Domain migration to reportedip.com**: all links, contact addresses and the default API endpoint now point to `reportedip.com` instead of `reportedip.de` (README, installer, admin panel, CMS template footers, license/security docs, `composer.json`)
- Default `api_url` is now `https://reportedip.com/wp-json/reportedip/v2/report`

### Added
- Automatic config migration: `Config::fromFile()` transparently rewrites an `api_url` still pointing at the legacy `reportedip.de` domain to `reportedip.com`, so existing installations report to the new domain without a manual config edit

## [1.3.5] - 2026-07-10

### Changed
- **Dashboard redesign**: the admin dashboard now surfaces all collected data sources in a restructured layout — KPI cards with a day-over-day trend chip ("Today" vs. yesterday), first-seen-today IP counter and queue-mode hint; a severity-distribution panel (critical/high/medium/low over the last 7 days, derived from category severities); a dark **Threat Intel** card with summary chips (canaries armed/triggered, captured payloads/volume) and live feeds of the latest triggered honeytokens and captured payloads; a "Top Targeted Paths" ranking (query strings stripped, last 7 days); and a webhook health badge on the Queue Processing card
- Dashboard KPIs (total, today, unique IPs, queue, triggered honeytokens) auto-refresh every 60 s via the existing `/api/stats` endpoint, which now also returns trend and threat-intel summaries
- Dashboard markup moved from ad-hoc inline styles to reusable design-system components in the admin layout (`rip-grid`, `rip-chart`, `rip-seg`, `rip-bar-list`, `rip-meter`/`rip-legend`, `rip-intel-card`/`rip-chip`/`rip-feed`, `rip-status-pill`, `rip-kv`, new `rip-alert--warning`/`--info` variants); the activity chart gained per-range totals/peak and a cleaner segmented range switcher
- New data providers: `Dashboard::getTrends()`, `getSeverityBreakdown()`, `getTopUris()`, `getIntelData()`, `getWebhookSummary()`; `ThreatIntel::getRecentTriggered()`, `getRecentCaptures()`

## [1.3.4] - 2026-07-10

### Fixed
- **Server-header fingerprint on the new bait traps**: `DbAdminTrap`, `WebshellTrap` and `SystemInfoTrap` did not set the spoofed `Server` header, so the real web server's `Server: nginx` (or similar) leaked through on `/phpmyadmin/`, `/adminer.php`, `/server-status`, `/actuator/*` and webshell paths — a mismatch versus the `Server: Apache/2.4.58` sent everywhere else that could out the honeypot. They now adopt the active profile's `Server` header (without the WordPress-specific `Link`/`X-Pingback` headers, which would themselves be out of place on those pages).

### Documentation
- `config/nginx.conf.example`, `config/apache.htaccess.example` and the README now document a deployment pitfall: default server hardening (common on managed hosting / ISPConfig / Plesk) blocks dotfiles (`.env`, `.git`) with `403` and serves `robots.txt` statically (`404`), so those requests never reach `index.php` and the source-leak/honeytoken and spider traps stay dormant. The nginx example now routes `.env`/`.git`/`.svn`/`robots.txt` through `index.php` via `^~`/`=` locations that outrank the `location ~ /\.` deny rule (with `/.well-known` left intact for ACME/TLS).
- The **Threat Intel** admin page now carries a built-in, collapsible explainer describing what honeytokens and captured payloads are and the safety model for viewing hostile payloads; the README gains a matching "Threat Intel" section.

## [1.3.3] - 2026-07-10

### Added
- **Honeytoken / canary credentials**: fake config leaks (`.env`, `.git/config`, phpMyAdmin) now embed credentials that are unique per source IP and persisted in the new `honeypot_honeytokens` table. Any later request that replays one of these values — from any IP — is a confirmed-malicious event (score 100, new category 59) with near-zero false positives. New `Honeytoken` service plus reuse detection wired into `App::handle()` (scans URI, body, POST values, cookies, Authorization header)
- **Source/secret disclosure traps** (`SourceLeakTrap`): convincing fake responses for the most-scanned disclosure paths — `.env` (with per-IP honeytokens for DB/AWS/JWT/mail secrets), `.git/config`, `.git/HEAD`, `.git/logs/HEAD`, `.git/index`, `.svn/entries`
- **Fake DB-admin panels** (`DbAdminTrap`): realistic phpMyAdmin 5.2.1 and Adminer 4.8.1 login screens; submitted credentials are captured for intel and login always "fails"
- **Fake server-info endpoints** (`SystemInfoTrap`): plausible output for `/server-status`, `/server-info` (Apache mod_status) and Spring Boot Actuator (`/actuator`, `/actuator/env`, `/actuator/health`)
- **Webshell trap** (`WebshellTrap`): serves an inert shell prompt for known webshell filenames and disguised uploads; any command/password POSTed is captured. New `WebshellAccessAnalyzer` (category 60)
- **Spider trap**: hidden bait paths advertised only in robots.txt (Disallow), the sitemap, and a hidden home-page link. Requesting one flags an automated crawler with almost no false positives. New `SpiderTrapAnalyzer` (category 63)
- **Indiscriminate-scan detection** (`ForeignFrameworkProbeAnalyzer`): probes for Tomcat, Solr, Jenkins, WebLogic, Telerik, Fortinet/Cisco VPN and similar non-CMS targets are flagged as blind mass-scanning (category 61)
- **Sticky admin**: known-username logins are occasionally "accepted" (configurable via `LoginTrap::STICKY_ADMIN_CHANCE`), dropping the attacker into the inert fake admin. Plugin/theme upload payloads are captured (`AdminTrap`) and the install always reports "Incompatible Archive"
- **Blind-SQLi tarpit**: requests carrying time-based payloads (`SLEEP`, `pg_sleep`, `BENCHMARK`, `WAITFOR DELAY`) get a deliberate response delay, so the attacker's tool "confirms" the injection and wastes its own time (`tarpit_enabled`, `tarpit_max_seconds`)
- New `honeypot_captures` table (`PayloadCapture` service) storing uploaded/POSTed payloads base64-encoded, capped at 256 KiB
- **Admin panel "Threat Intel" page** (`src/Admin/ThreatIntel.php`): tabbed view of issued/triggered honeytokens (with leaking vs. reusing IP) and captured payloads, plus a per-payload detail view. Attacker payloads are rendered strictly as escaped, inert text (control bytes neutralized) with a raw-download option served as `application/octet-stream`
- New reporting categories 59–63 (Honeytoken Triggered, Webshell Access, Indiscriminate Scan, Source Code Disclosure, Spider Trap); detection pipeline grew from 36 to 39 analyzers
- 33 new tests covering the three new analyzers, the honeytoken service, the threat-intel reader, and end-to-end leak→reuse and admin-render verifications

## [1.3.2] - 2026-06-17

### Fixed
- Retry-storm protection: `ReportClient` now applies an exponential backoff (5s → max. 300s) on all transient failures, not just HTTP 429. This covers 5xx server errors, 408 (Request Timeout), 499 (nginx "Client Closed Request") and cURL/connection errors — exactly the codes produced when the API is overloaded. Previously the server kept hammering on 502/503/499 without any backoff and amplified the overload
- Backoff state is persisted to `data/report_backoff.json`. Under the web-cron model every page visit builds a fresh `ReportClient`, so the former in-memory backoff never survived a single request and was effectively useless
- 499 and 408 are no longer treated as permanent rejections — such reports are retried after a backoff instead of being dropped
- Rate limit (default 60/min) is persisted to `data/report_ratelimit.json` and advanced atomically via `flock`; the cap is therefore enforced globally across all requests/processes instead of only within a single client instance
- `ReportQueue` now stops a batch cleanly while a backoff or rate limit is active, instead of running every remaining entry through and inflating its `failed_attempts` counter without anything being sent

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
