# ReportedIP Honeypot Server

[![License: BSL 1.1](https://img.shields.io/badge/License-BSL%201.1-blue.svg)](LICENSE)
[![PHP: 8.2+](https://img.shields.io/badge/PHP-8.2%2B-777BB4.svg)](https://php.net)

A standalone PHP honeypot server that emulates CMS installations (WordPress, Drupal, Joomla) to detect and report malicious traffic to the [reportedip.com](https://reportedip.com) API.

Zero external Composer dependencies. Runs on vanilla PHP 8.2+. Uses SQLite for persistence.

---

> **We're looking for testers and community members!**
>
> We are actively searching for test users and contributors who want to help improve the data quality and detection coverage of [reportedip.com](https://reportedip.com). Every honeypot instance you run contributes attack data that helps protect the entire community.
>
> **To get started, you need a Community Access Key (API key).** Please contact us at **[1@reportedip.com](mailto:1@reportedip.com)** to request your key. It's free.
>
> Whether you're running a small VPS, a shared hosting account, or a dedicated server — every installation helps.

---

## Features

- **CMS Emulation** — Realistic WordPress, Drupal, and Joomla front-ends with login pages, admin panels, REST APIs, RSS feeds, sitemaps, and vulnerability paths
- **39 Threat Analyzers** — SQL injection, XSS, path traversal, brute force, credential stuffing, SSRF, XML-RPC abuse, plugin exploits, config file access, webshell access, indiscriminate framework scanning, and more
- **High-Interaction Traps & Honeytokens** — Fake config leaks (`.env`, `.git`, phpMyAdmin) embed per-IP canary credentials; replaying one is a confirmed-malicious event with near-zero false positives. Includes a spider trap, a blind-SQLi tarpit, and a sticky fake admin that captures uploaded plugin/theme payloads (see [High-Interaction Traps](#high-interaction-traps--honeytokens))
- **Automatic Reporting** — Detected threats are queued and batch-reported to the reportedip.com API with rate limiting and exponential backoff
- **Webhooks** — Forward detections in real time to your own logging/SIEM systems or third-party abuse databases (AbuseIPDB, Slack, Discord, custom APIs) with configurable methods, headers, body templates, and optional HMAC-SHA256 signatures
- **Admin Dashboard** — Web-based panel for monitoring attacks, viewing statistics, inspecting captured payloads and triggered honeytokens, managing whitelists, and generating AI content
- **AI Content Generation** — Optional OpenAI integration to generate realistic blog posts for the fake CMS (AJAX-based, one post at a time to avoid timeouts)
- **Bot Detection** — Classifies visitors as good bots, bad bots, AI agents, hackers, or humans
- **Cloudflare Support** — Real IP resolution behind Cloudflare and custom reverse proxies via trusted_proxies config
- **Security Hardened** — CSRF protection, bcrypt auth, brute-force lockout, security headers (CSP, X-Frame-Options, HSTS), session IP binding
- **Docker Ready** — Ships with Dockerfile and docker-compose for instant deployment
- **Zero Dependencies** — No external Composer packages; built-in PSR-4 autoloader fallback

## Requirements

- PHP 8.2+
- Extensions: `pdo_sqlite`, `curl`, `json`
- Web server (nginx or Apache) with all requests routed to `public/index.php`

## Quick Start

### Docker

```bash
git clone https://github.com/reportedip/honeypot-server.git
cd honeypot-server
docker compose -f docker/docker-compose.yml up -d
```

Open the container URL in your browser — the web installer starts automatically on first visit.

### Manual Installation

```bash
git clone https://github.com/reportedip/honeypot-server.git
cd honeypot-server
```

Configure your web server:

- **nginx** — Copy `config/nginx.conf.example` and adjust paths
- **Apache** — Copy `config/apache.htaccess.example` to your document root

> **Important — route *all* requests to `index.php`, including dotfiles.**
> Several traps depend on requests for `.env`, `.git/config`, `.svn/`, and `robots.txt` reaching the honeypot (the source-leak trap that issues honeytokens, and the spider trap). Default server hardening — common on managed hosting and control panels like ISPConfig/Plesk — blocks dotfiles with a `403` and serves `robots.txt` statically (`404` when absent), so those requests never reach `public/index.php` and the traps silently stay dormant.
>
> The shipped `nginx.conf.example` already routes these paths through `index.php` (via `^~ /.env`, `^~ /.git`, `^~ /.svn`, `= /robots.txt` locations that outrank the `location ~ /\.` deny rule). On Apache, make sure no global `<FilesMatch "^\.">` / `<DirectoryMatch /\.git>` deny rule blocks them for this vhost. Keep `/.well-known/` allowed so ACME/TLS still works.
>
> **Quick check:** `curl -s https://your-honeypot/.env` should return a fake `.env` with `APP_KEY`/`DB_PASSWORD` values (served with the spoofed `Server: Apache` header) — not a `403` from your real web server.

Then open the website URL in your browser. The web installer starts automatically when no `config/config.php` exists and guides you through:

1. System requirements check (PHP 8.2+, required extensions)
2. Community Access Key — contact **[1@reportedip.com](mailto:1@reportedip.com)** to get yours (free)
3. CMS profile selection (WordPress / Drupal / Joomla)
4. Admin panel path and password
5. Optional AI content settings (OpenAI API key, model, language)
6. Automatic initialization (database, directories, IP whitelist)

### Queue Processing

By default, the honeypot uses **web cron mode**: the report queue is automatically processed in small batches (2 reports) after every page visit. No external cron job is needed. This is ideal for shared hosting.

For high-traffic installations, switch to **cron mode** in `config/config.php`:

```php
'queue_mode' => 'cron',
```

Then set up a cron job:

```bash
# Process the report queue silently every 5 minutes
*/5 * * * * php /path/to/honeypot-server/cli.php process-queue > /dev/null 2>&1
```

To capture CLI output for debugging, redirect to `>> data/cron.log 2>&1` instead. Log files (`cron.log`, `api_errors.log`) are automatically rotated when exceeding 2 MB. Cleanup of old database entries runs automatically in both modes.

#### Whitelist mirroring

The API keeps its own whitelist of verified search-engine crawlers and other addresses that must not be reported. When it rejects a report for such an IP (HTTP 400, `ip_whitelisted`), the honeypot copies that verdict into the local whitelist for **7 days**, described as `Auto: <category>: <reason> (reportedip.com)`. Those requests then stop being detected, queued and sent at all, instead of producing a rejected report every time.

The entry expires on its own, so an IP that loses its upstream whitelisting is reported again afterwards; expired entries are removed by the regular cleanup. Whitelist entries you added yourself never get an expiry, and mirroring never puts one on them.

## Configuration

All settings are in `config/config.php` (generated by the installer). See `config/config.example.php` for defaults and documentation.

### Core Settings

| Option | Default | Description |
|---|---|---|
| `api_key` | `''` | Community Access Key — request at [1@reportedip.com](mailto:1@reportedip.com) |
| `api_url` | `'https://reportedip.com/...'` | API endpoint URL |
| `cms_profile` | `'wordpress'` | CMS to emulate: `wordpress`, `drupal`, `joomla` |
| `admin_path` | `'/_hp_admin'` | Path to the honeypot admin panel |
| `admin_password_hash` | `''` | Bcrypt hash (set by installer) |
| `db_path` | `'data/honeypot.sqlite'` | SQLite database path |
| `trusted_proxies` | Cloudflare CIDRs | Trusted proxy IP ranges for real IP resolution |
| `debug` | `false` | Enable verbose error output |

### Rate Limiting & Retention

| Option | Default | Description |
|---|---|---|
| `rate_limit_per_ip` | `10` | Max log entries per IP per minute |
| `report_rate_limit` | `60` | Max API reports per minute |
| `report_batch_size` | `10` | Reports per cron batch |
| `queue_mode` | `'web'` | `'web'` (automatic) or `'cron'` (manual via cli.php) |
| `log_retention_days` | `90` | Days to keep log entries |
| `tarpit_enabled` | `true` | Delay the response on time-based blind SQL injection payloads |
| `tarpit_max_seconds` | `6` | Maximum tarpit delay (clamped to 1–15 seconds) |

### AI Content Generation (Optional)

| Option | Default | Description |
|---|---|---|
| `openai_api_key` | `''` | OpenAI API key (enables content generation) |
| `openai_base_url` | `'https://api.openai.com/v1'` | API base URL (change for compatible providers) |
| `openai_model` | `'gpt-4o-mini'` | Model to use for generation |
| `content_language` | `'en'` | Default language (`en` or `de`) |
| `content_niche` | `''` | Default topic niche for posts |

## CMS Profiles

Each profile emulates a specific CMS with realistic URL patterns, HTTP headers, and response templates:

| Profile | Emulated Paths | Fake Headers |
|---|---|---|
| **WordPress** | `wp-login.php`, `wp-admin/`, `wp-json/`, `xmlrpc.php`, `/feed/`, plugin paths | `X-Pingback`, `Link: wp-json`, `Server: Apache` |
| **Drupal** | `user/login`, `admin/`, `jsonapi/`, `update.php`, module paths | `X-Generator: Drupal 10`, `X-Drupal-Cache` |
| **Joomla** | `administrator/`, `api/`, `component/` paths | `X-Content-Encoded-By: Joomla! 4.4` |

## Detection System

The `DetectionPipeline` runs 40 analyzers on every request:

| Analyzer | Detects |
|---|---|
| `SqlInjectionAnalyzer` | SQL injection in query params, POST data, headers |
| `XssAnalyzer` | Cross-site scripting via script tags, event handlers |
| `PathTraversalAnalyzer` | Directory traversal (`../`, encoded variants) |
| `BruteForceAnalyzer` | Repeated login attempts |
| `CredentialStuffingAnalyzer` | Common username/password combinations |
| `PathScanningAnalyzer` | Probing for admin panels, backup files |
| `PluginExploitAnalyzer` | Known CMS plugin vulnerability paths |
| `ConfigAccessAnalyzer` | Attempts to access `.env`, `wp-config.php`, etc. |
| `VulnerabilityProbeAnalyzer` | Shellshock, Log4Shell, PHPUnit exploits |
| `RestBatchExploitAnalyzer` | WordPress REST batch endpoint exploitation (wp2shell / CVE-2026-63030) |
| `XmlRpcAnalyzer` | XML-RPC pingback abuse, method enumeration |
| `UserAgentAnalyzer` | Malicious tools (sqlmap, nikto, dirbuster) |
| `HeaderAnomalyAnalyzer` | Missing/suspicious HTTP headers |
| `HttpVerbAnalyzer` | Unusual HTTP methods (TRACE, DELETE, etc.) |
| `SsrfAnalyzer` | Server-side request forgery attempts |
| `FormSpamAnalyzer` | Spam submissions via comment/contact forms |
| `ThemeExploitAnalyzer` | Theme vulnerability exploitation, TimThumb access, theme editor abuse |
| `UserEnumerationAnalyzer` | User enumeration via author params, REST API, sitemaps |
| `FileUploadMalwareAnalyzer` | Malicious file uploads, double extensions, PHP code signatures |
| `AdminDirectoryScanningAnalyzer` | CMS admin directory scanning and probing |
| `ResourceExhaustionAnalyzer` | DoS attacks, oversized requests, regex DoS, XML entity expansion |
| `WpCronAbuseAnalyzer` | WP-Cron abuse, heartbeat abuse, REST API bulk operations |
| `VersionFingerprintingAnalyzer` | CMS version fingerprinting via readme/license files, version params |
| `DatabaseBackupAccessAnalyzer` | Database dump and backup file access attempts |
| `RegistrationHoneypotAnalyzer` | Automated registration spam, disposable emails, bot patterns |
| `SearchSpamAnalyzer` | Search functionality abuse, injection via search params |
| `TrackbackPingbackSpamAnalyzer` | Trackback/pingback spam, DDoS amplification |
| `MediaLibraryAbuseAnalyzer` | Media library abuse, upload directory scanning |
| `WpCliAbuseAnalyzer` | WP-CLI abuse, dangerous AJAX actions, object injection |
| `CoreFileModificationAnalyzer` | Core file modification via plugin/theme editors |
| `AjaxEndpointAbuseAnalyzer` | AJAX and admin-post endpoint abuse |
| `OpenRedirectAnalyzer` | Open redirect attacks, JavaScript protocol handlers |
| `PasswordResetAbuseAnalyzer` | Password reset abuse, Host header injection |
| `SessionHijackingAnalyzer` | Session hijacking, cookie manipulation, session fixation |
| `UnicodeEncodingAttackAnalyzer` | Unicode/encoding bypass attacks, overlong UTF-8, null bytes |
| `RateLimitBypassAnalyzer` | Rate limit bypass via header spoofing, proxy chain manipulation |
| `JavaScriptInjectionAnalyzer` | JS injection, DOM-based XSS, prototype pollution |
| `WebshellAccessAnalyzer` | Access to known webshell/backdoor filenames, uploaded scripts, double extensions |
| `ForeignFrameworkProbeAnalyzer` | Indiscriminate scans for Tomcat, Solr, Jenkins, WebLogic, Telerik, VPN appliances |
| `SpiderTrapAnalyzer` | Requests to hidden bait paths advertised only in robots.txt/sitemap |

Each detection produces a `DetectionResult` with category IDs (mapped to reportedip.com categories), severity score (1-100), and a human-readable comment.

Detections that only reach the honeypot's own bait surface use the reporting categories 59–63: *Honeytoken Triggered*, *Webshell Access*, *Indiscriminate Scan*, *Source Code Disclosure*, and *Spider Trap*.

## High-Interaction Traps & Honeytokens

Beyond passive detection, the honeypot actively engages attackers to gather higher-confidence signals and threat intel.

- **Honeytokens (canary credentials)** — When an attacker grabs a fake config file (`.env`, `.git/config`, phpMyAdmin), the response embeds credentials that are **unique per source IP** and persisted in the `honeypot_honeytokens` table. Any later request that replays one of those values — from *any* IP — is flagged as *Honeytoken Triggered* (severity 100). Since the value only ever existed inside a hidden honeypot response, this has near-zero false positives and correlates the leaking IP with the reusing IP.
- **Source/secret disclosure traps** — `.env`, `.git/config`, `.git/HEAD`, `.git/logs/HEAD`, `.git/index`, and `.svn/entries` return convincing fake content instead of a bare 404, keeping DVCS-ripper tools engaged.
- **Fake DB-admin panels** — Realistic phpMyAdmin and Adminer login screens; submitted credentials are captured.
- **Fake server-info endpoints** — Plausible output for `/server-status`, `/server-info`, and Spring Boot Actuator (`/actuator/env`, `/actuator/health`).
- **Webshell trap** — Known webshell filenames and disguised uploads get an inert shell prompt; any command or password POSTed is captured (no code is ever executed).
- **Spider trap** — Bait paths advertised only in robots.txt (Disallow), the sitemap, and a hidden home-page link. Any request to one is an automated crawler, not a human.
- **Sticky fake admin** — A configurable fraction of known-username logins are "accepted", dropping the attacker into an inert fake admin. Plugin/theme upload attempts are captured for intel and the install always reports "Incompatible Archive".
- **Blind-SQLi tarpit** — Requests carrying time-based payloads (`SLEEP`, `pg_sleep`, `BENCHMARK`, `WAITFOR DELAY`) get a deliberate response delay, so the attacker's tool "confirms" the injection and wastes its own time.

Captured payloads (uploads, webshell POSTs, DB-admin logins) are stored base64-encoded (capped at 256 KiB) in the `honeypot_captures` table and are viewable under **Threat Intel** in the admin panel. Both tables are created automatically on upgrade — no manual migration.

## Admin Panel

Access the admin panel at your configured path (default: `/_hp_admin`).

### Pages

- **Dashboard** — Attack statistics, activity chart, top IPs, top categories, cron status, system info
- **Logs** — Filterable attack log with search, IP filter, category filter, status filter
- **Whitelist** — Add/remove IPs and CIDR ranges from the whitelist; entries mirrored from the API's own whitelist show their expiry
- **Content** — Manage AI-generated blog posts for the fake CMS
- **Visitors** — Bot/visitor classification log with type breakdown; the summary cards filter the log by visitor type
- **Threat Intel** — Issued/triggered honeytokens and captured attacker payloads (see below)
- **Webhooks** — Manage external report targets (see [Webhooks](#webhooks))
- **Updates** — Self-update via GitHub Releases with backups and rollback

### Threat Intel

Where **Logs** records every suspicious request, the **Threat Intel** page shows what attackers left behind after engaging with the high-interaction traps. It has two tabs plus summary counters (honeytokens issued/triggered, payloads captured, captured volume).

**Honeytokens** — the canary credentials leaked by the fake-config traps (`.env`, `.git/config`, phpMyAdmin). Each token is unique per source IP and listed as **Armed** until it is replayed against the honeypot — from any IP — at which point it flips to **Triggered**: a confirmed-malicious event (category 59, severity 100) with near-zero false positives, since the value only ever existed inside a hidden honeypot response. The list pairs the IP a token was *leaked to* with the IP that *reused* it, plus a hit counter.

**Captured Payloads** — the raw data attackers submitted to the traps: uploaded plugin/theme archives from the sticky fake admin, commands and passwords POSTed to the webshell trap, and logins to the fake phpMyAdmin/Adminer panels. Stored base64-encoded in `honeypot_captures` (capped at 256 KiB per payload). *View* opens a detail page; *Download raw* returns the original bytes.

> **Safety:** captured payloads are attacker-controlled and may be hostile (real webshells, malware archives). They are rendered only as escaped, inert text with control bytes neutralised — never executed or shown as active markup — and the raw download is served as a plain `application/octet-stream` attachment.

### Security Features

- Bcrypt password authentication with brute-force lockout (5 attempts, 15-minute window)
- CSRF protection on all state-changing actions (including logout)
- Session IP binding to prevent session hijacking
- Security headers: `X-Frame-Options: DENY`, `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, `Cache-Control: no-store`
- `SameSite=Strict` and `HttpOnly` session cookies

## Webhooks

Besides the automatic reporting to reportedip.com, the honeypot can forward every detection to your own systems (SIEM, log management, chat alerts, custom dashboards) or third-party abuse databases like **AbuseIPDB** in real time. Webhooks are managed in the admin panel under **Webhooks**.

### How It Works

- Each webhook is an HTTP(S) endpoint that receives a request for every matching detection
- HTTP method (`POST`/`PUT`/`PATCH`/`GET`), custom headers (e.g. API keys), and body format are configurable per endpoint
- Delivery happens after the trap response has been sent to the attacker, so webhooks never slow down the honeypot
- **Filters**: restrict a webhook to specific category IDs and/or analyzer names. Empty filters = all detections. When both filters are set, the webhook triggers when *either* one matches
- **Test button**: every webhook can be verified from the admin panel with a test delivery (`X-ReportedIP-Event: test`). Test deliveries use the loopback IP `127.0.0.1`, so abuse databases reject them instead of storing a real report
- Delivery status, timestamp, and consecutive failure count are shown per webhook
- **Quick presets** in the admin form fill in URL, method, headers, and body template for AbuseIPDB, Slack, Discord, and generic JSON — just add your API key afterwards

### Body Formats

| Format | Description |
|---|---|
| `json` | Full structured detection payload (see below) — default |
| `form` | Flat key/value fields as `application/x-www-form-urlencoded` |
| `custom` | Free-form body template with placeholders — adapts to any third-party API |

### Template Placeholders

Available in custom body templates **and** in the endpoint URL (for GET-style APIs):

`{{ip}}`, `{{categories}}`, `{{abuseipdb_categories}}`, `{{comment}}`, `{{severity}}`, `{{analyzers}}`, `{{uri}}`, `{{method}}`, `{{user_agent}}`, `{{host}}`, `{{timestamp}}`, `{{version}}`, `{{event}}`

Each placeholder also exists as `{{name_url}}` (URL-encoded) and `{{name_json}}` (JSON-escaped). Multiple detections in one request are aggregated: categories are merged, severity is the maximum, comments are joined.

`{{abuseipdb_categories}}` automatically translates reportedip.com category IDs to AbuseIPDB category IDs (IDs 1–23 are identical on both platforms; the CMS- and honeypot-specific IDs 24–63 map to their closest equivalent, e.g. *WP Login Brute Force* → *Brute-Force* + *Web App Attack*).

### Example: Reporting to AbuseIPDB

Use the **AbuseIPDB preset** in the admin form, or configure manually:

| Field | Value |
|---|---|
| URL | `https://api.abuseipdb.com/api/v2/report` |
| Method | `POST` |
| Body format | `custom` |
| Headers | `Key: YOUR_ABUSEIPDB_API_KEY`<br>`Accept: application/json` |
| Body template | `ip={{ip_url}}&categories={{abuseipdb_categories}}&comment={{comment_url}}` |

Note: AbuseIPDB accepts a report for the same IP only once every 15 minutes per reporter. The honeypot's built-in category cooldown (15 minutes by default) keeps duplicate submissions to a minimum; rejected duplicates show up as a delivery failure (`HTTP 429`) in the webhook status.

### Request Headers

| Header | Value |
|---|---|
| `Content-Type` | `application/json` (format `json`), `application/x-www-form-urlencoded` (format `form`); for `custom` it is derived from the rendered body and can be overridden via custom headers |
| `User-Agent` | `reportedip-honeypot-server/<version>` |
| `X-ReportedIP-Event` | `detection` or `test` |
| `X-ReportedIP-Signature` | `sha256=<HMAC>` — only when a secret is configured |

Custom headers configured on the webhook override the defaults (e.g. a custom `Content-Type`).

### JSON Payload (body format `json`)

```json
{
  "event": "detection",
  "generated_at": "2026-06-12T14:00:00+00:00",
  "honeypot": {
    "name": "reportedip-honeypot-server",
    "version": "1.3.1",
    "host": "your-honeypot.example.com",
    "profile": "wordpress"
  },
  "request": {
    "ip": "203.0.113.50",
    "method": "POST",
    "uri": "/wp-login.php",
    "user_agent": "sqlmap/1.7"
  },
  "detections": [
    {
      "analyzer": "SqlInjection",
      "categories": [16, 45],
      "category_names": ["SQL Injection", "Code Injection"],
      "comment": "SQL injection attempt detected: ...",
      "severity": 85
    }
  ]
}
```

### Verifying Signatures

When a secret is configured, verify the integrity of each delivery by computing the HMAC over the raw request body:

```php
$expected = 'sha256=' . hash_hmac('sha256', $rawBody, $secret);
$valid = hash_equals($expected, $_SERVER['HTTP_X_REPORTEDIP_SIGNATURE'] ?? '');
```

## CLI Commands

```bash
php cli.php stats                        # Show attack statistics
php cli.php process-queue                # Send pending reports to API
php cli.php cleanup [--days=90]          # Remove old log entries
php cli.php whitelist-add <ip> [desc]    # Add IP/CIDR to whitelist
php cli.php whitelist-remove <ip>        # Remove IP from whitelist
php cli.php whitelist-list               # Show all whitelist entries
php cli.php test-api                     # Test API connectivity
```

## Project Structure

```
reportedip-honeypot-server/
├── public/index.php              # Single entry point (document root)
├── cli.php                       # CLI tool for cron and management
├── config/
│   ├── config.example.php        # Configuration template
│   ├── nginx.conf.example        # Nginx config template
│   └── apache.htaccess.example   # Apache config template
├── src/
│   ├── Core/                     # App, Request, Response, Router, Config, Cache
│   ├── Detection/                # DetectionPipeline + 39 Analyzers, Honeytoken, SpiderTrap
│   ├── Network/                  # IpResolver, CidrMatcher
│   ├── Persistence/              # Database, Logger, VisitorLogger, Whitelist, PayloadCapture
│   ├── Api/                      # ReportClient, ReportQueue
│   ├── Profile/                  # CmsProfile, WordPress/Drupal/Joomla profiles
│   ├── Content/                  # ContentGenerator, ContentRepository
│   ├── Admin/                    # AdminController, AdminAuth, Dashboard, LogViewer, ThreatIntel
│   └── Trap/                     # 17 trap handlers (Login, Admin, SourceLeak, DbAdmin, Webshell, ...)
├── templates/
│   ├── admin/                    # Admin panel templates (layout, dashboard, logs, ...)
│   ├── wordpress/                # WordPress trap templates
│   ├── drupal/                   # Drupal trap templates
│   └── joomla/                   # Joomla trap templates
├── tests/                        # 398+ tests (unit + analyzer + integration)
├── docker/                       # Dockerfile, docker-compose.yml, nginx/php-fpm configs
└── data/                         # SQLite DB, cache, logs (gitignored)
```

## Testing

The project uses a custom lightweight test framework (no PHPUnit dependency):

```bash
php tests/run-tests.php                  # Run all tests
php tests/run-tests.php --integration    # Include integration tests
php tests/run-tests.php --filter Config  # Filter by class name
php tests/run-tests.php --verbose        # Show timing per test
```

## How It Works

1. All HTTP requests hit `public/index.php`
2. `IpResolver` determines the real client IP (Cloudflare/proxy-aware)
3. `Router` checks if the request targets the admin panel
4. For honeypot requests: `Whitelist` check, then `DetectionPipeline` runs all 40 analyzers
5. Detections are logged to SQLite with `sent=0` (queued for reporting)
6. `Router` matches the path against the active CMS profile to select a trap
7. The trap renders a convincing CMS-like response (login page, blog post, RSS feed, etc.)
8. After the response is sent, web cron processes a micro-batch of queued reports to the reportedip.com API (or a cron job does it in cron mode)

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Author

**Patrick Schlesinger**
- Website: [reportedip.com](https://reportedip.com)
- Email: 1@reportedip.com

## License

This project is licensed under the **Business Source License 1.1** (BSL 1.1).

- **Production use is permitted** (including by companies), EXCEPT offering this software as a hosted/managed service to third parties or selling it as a commercial product.
- On **2030-03-01**, the license automatically converts to **Apache License 2.0**.

See [LICENSE](LICENSE) for the full text.

## Legal / Disclaimer

**By using this software, you agree to the terms in [DISCLAIMER.md](DISCLAIMER.md).**

- **No Warranty**: This software is provided "AS IS" without warranty of any kind.
- **Legal Compliance**: You are solely responsible for compliance with all applicable laws in your jurisdiction regarding honeypot operation and data collection.
- **Data Privacy**: You are the data controller for any personal data (IP addresses) collected by this software.
- **Risk**: Running a honeypot involves inherent security risks. The authors are not liable for any damages.

**Bitte beachten Sie den ausführlichen Haftungsausschluss in [DISCLAIMER.md](DISCLAIMER.md).**
