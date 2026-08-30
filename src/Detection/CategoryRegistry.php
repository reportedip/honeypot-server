<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection;

/**
 * Registry of all reportedip.com attack category IDs.
 *
 * Maps numeric category IDs (used by the API) to human-readable names,
 * descriptions, and severity levels. Categories 1-30 are general security
 * categories, 31-58 are WordPress-specific, 59-63 come from the
 * high-interaction honeypot traps.
 *
 * Names and severity levels MIRROR the API catalogue
 * (`GET /wp-json/reportedip/v2/categories`) and must not drift from it: the
 * API rejects a whole report with HTTP 400 as soon as one ID is unknown to it,
 * and an ID whose meaning differs locally gets filed under the wrong threat
 * upstream. `CategoryRegistryTest` pins this table to the catalogue.
 */
final class CategoryRegistry
{
    /**
     * Complete category mapping table.
     *
     * Each entry: [name, description, severity (1-10)]
     *
     * @var array<int, array{string, string, int}>
     */
    private const CATEGORIES = [
        // General security categories (1-30) - mirror of the API catalogue
        1  => ['DNS Compromise', 'DNS-Server kompromittiert oder gekapert', 8],
        2  => ['DNS Poisoning', 'DNS-Cache-Vergiftung oder DNS-Spoofing', 9],
        3  => ['Fraud Orders', 'Betrügerische Bestellungen in Online-Shops', 6],
        4  => ['DDoS Attack', 'Distributed Denial of Service Angriff', 9],
        5  => ['FTP Brute-Force', 'FTP-Login Brute-Force Angriff', 7],
        6  => ['Ping of Death', 'Überlange Ping-Pakete (Ping of Death)', 8],
        7  => ['Phishing', 'Phishing-Seiten gehostet oder verbreitet', 9],
        8  => ['Fraud VoIP', 'VoIP-Betrug und Gebührenmissbrauch', 6],
        9  => ['Open Proxy', 'Offener Proxy zur Weiterleitung von Missbrauch', 5],
        10 => ['Web Spam', 'Spam auf Websites und in Foren', 4],
        11 => ['Email Spam', 'Versand unerwünschter Massen-E-Mails', 4],
        12 => ['Blog Spam', 'Spam-Kommentare in Blogs', 3],
        13 => ['VPN IP', 'VPN-Exit-Node (geringe direkte Bedrohung)', 2],
        14 => ['Port Scan', 'Port-Scanning und Dienst-Erkundung', 6],
        15 => ['Hacking', 'Allgemeiner Hacking-Versuch', 8],
        16 => ['SQL Injection', 'SQL-Injection Angriff auf Datenbank', 9],
        17 => ['Spoofing', 'IP- oder E-Mail-Spoofing', 7],
        18 => ['Brute-Force', 'Brute-Force auf Zugangsdaten', 7],
        19 => ['Bad Web Bot', 'Bösartiger oder missbräuchlicher Web-Bot', 5],
        20 => ['Exploited Host', 'Kompromittierter Host unter Kontrolle eines Angreifers', 8],
        21 => ['Web App Attack', 'Angriff auf Webanwendung', 8],
        22 => ['SSH', 'SSH-Brute-Force und -Missbrauch', 7],
        23 => ['IoT Targeted', 'Angriff gezielt auf IoT-Geräte', 8],
        24 => ['Cryptocurrency Mining', 'Unerlaubtes Krypto-Mining', 6],
        25 => ['Ransomware C&C', 'Ransomware Command-and-Control Infrastruktur', 10],
        26 => ['Banking Trojan', 'Verbreitung oder Steuerung eines Banking-Trojaners', 10],
        27 => ['Mobile Malware', 'Verbreitung mobiler Schadsoftware', 8],
        28 => ['Supply Chain Attack', 'Angriff auf die Software-Lieferkette', 10],
        29 => ['Zero-Day Exploit', 'Ausnutzung einer ungepatchten Zero-Day-Lücke', 10],
        30 => ['Nation State', 'Staatlich gesteuerte Angriffsaktivität', 10],

        // WordPress-specific categories (31-58)
        31 => ['WP Login Brute Force', 'Brute-Force auf wp-login.php', 7],
        32 => ['WP Admin Brute Force', 'Angriff auf den WordPress-Adminbereich', 8],
        33 => ['WP XML-RPC Brute Force', 'Missbrauch der XML-RPC-Schnittstelle', 8],
        34 => ['WP REST API Abuse', 'Missbrauch der WordPress REST API', 7],
        35 => ['WP Plugin Exploit', 'Ausnutzung einer Plugin-Schwachstelle', 8],
        36 => ['WP Theme Exploit', 'Ausnutzung einer Theme-Schwachstelle', 8],
        37 => ['WP Core Exploit', 'Angriff auf Schwachstellen im WordPress-Core', 9],
        38 => ['WP Zero-Day Exploit', 'Unbekannter WordPress-Exploit (Zero-Day)', 10],
        39 => ['WP Comment Spam', 'Spam in WordPress-Kommentaren', 3],
        40 => ['WP Contact Form Spam', 'Spam über Kontaktformulare', 4],
        41 => ['WP Registration Spam', 'Registrierung gefälschter Benutzerkonten', 5],
        42 => ['WP Trackback Spam', 'Trackback- und Pingback-Spam', 6],
        43 => ['WP File Upload Malware', 'Upload von Schadsoftware über WordPress', 9],
        44 => ['WP Code Injection', 'PHP- oder JavaScript-Code-Injection', 9],
        45 => ['WP Database Injection', 'SQL-Injection in WordPress', 10],
        46 => ['WP Backdoor Installation', 'Installation einer Hintertür', 10],
        47 => ['WP SEO Spam', 'SEO-Spam und Link-Injection', 6],
        48 => ['WP Content Scraping', 'Automatisiertes Auslesen von Inhalten', 5],
        49 => ['WP Fake SEO Bot', 'Bösartiger SEO-Crawler', 6],
        50 => ['WP Redirect Hijacking', 'Manipulation von Weiterleitungen', 7],
        51 => ['WP Resource Exhaustion', 'Denial of Service durch Ressourcenverbrauch', 7],
        52 => ['WP Media Library Abuse', 'Missbrauch der Mediathek', 5],
        53 => ['WP Search Abuse', 'Überlastung der Suchfunktion', 4],
        54 => ['WP Cron Abuse', 'Missbrauch von WP-Cron', 6],
        55 => ['WP User Enumeration', 'Aufzählung von WordPress-Benutzern', 6],
        56 => ['WP Version Scanning', 'Scan nach der WordPress-Version', 7],
        57 => ['WP Plugin Scanning', 'Erkennung installierter Plugins', 7],
        58 => ['WP Config Exposure', 'Zugriff auf wp-config.php', 8],

        // Honeypot high-interaction categories (59-63)
        59 => ['Honeytoken Triggered', 'Geleakte Köder-Zugangsdaten wiederverwendet (bestätigt bösartig)', 10],
        60 => ['Webshell Access', 'Zugriff auf bekannte Webshell- oder Backdoor-Datei', 9],
        61 => ['Indiscriminate Scan', 'Wahllose Scans nach fremden Frameworks (Tomcat, Solr, Jenkins u. a.)', 6],
        62 => ['Source Code Disclosure', 'Zugriff auf offengelegte Quellcode-Metadaten (.git, .svn, .env)', 8],
        63 => ['Spider Trap', 'Abruf eines versteckten Köder-Pfads aus robots.txt/Sitemap', 5],
    ];

    /**
     * Get the English name for a category ID.
     */
    public static function getName(int $id): string
    {
        return self::CATEGORIES[$id][0] ?? 'Unknown (' . $id . ')';
    }

    /**
     * Get the German description for a category ID.
     */
    public static function getDescription(int $id): string
    {
        return self::CATEGORIES[$id][1] ?? 'Unbekannte Kategorie';
    }

    /**
     * Get the severity level (1-10) for a category ID.
     */
    public static function getSeverity(int $id): int
    {
        return self::CATEGORIES[$id][2] ?? 5;
    }

    /**
     * Get all categories as an associative array.
     *
     * @return array<int, array{name: string, description: string, severity: int}>
     */
    public static function getAll(): array
    {
        $result = [];
        foreach (self::CATEGORIES as $id => [$name, $description, $severity]) {
            $result[$id] = [
                'name'        => $name,
                'description' => $description,
                'severity'    => $severity,
            ];
        }
        return $result;
    }

    /**
     * Get the CSS severity class for a category ID.
     *
     * @return string One of: critical, high, medium, low
     */
    public static function getSeverityClass(int $id): string
    {
        $severity = self::getSeverity($id);

        if ($severity >= 8) {
            return 'critical';
        }
        if ($severity >= 5) {
            return 'high';
        }
        if ($severity >= 3) {
            return 'medium';
        }
        return 'low';
    }

    /**
     * Format a comma-separated category string as HTML badges with names and severity colors.
     *
     * @param string $categoryCsv Comma-separated category IDs (e.g. "16,45")
     * @return string HTML badges
     */
    public static function formatBadges(string $categoryCsv): string
    {
        $badges = '';
        foreach (explode(',', $categoryCsv) as $cat) {
            $cat = trim($cat);
            if ($cat === '' || !is_numeric($cat)) {
                continue;
            }
            $id = (int) $cat;
            $name = htmlspecialchars(self::getName($id), ENT_QUOTES, 'UTF-8');
            $class = self::getSeverityClass($id);
            $badges .= sprintf(
                '<span class="rip-badge rip-badge--severity-%s" title="%s">%s (%d)</span>',
                $class,
                htmlspecialchars(self::getDescription($id), ENT_QUOTES, 'UTF-8'),
                $name,
                $id
            );
        }
        if ($badges === '') {
            return '';
        }
        return '<span class="rip-badge-group">' . $badges . '</span>';
    }

    /**
     * Check if a category ID exists.
     */
    public static function exists(int $id): bool
    {
        return isset(self::CATEGORIES[$id]);
    }
}
