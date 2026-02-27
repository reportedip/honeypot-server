# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
