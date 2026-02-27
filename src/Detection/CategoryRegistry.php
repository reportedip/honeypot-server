<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection;

/**
 * Registry of all reportedip.de attack category IDs.
 *
 * Maps numeric category IDs (used by the API) to human-readable names,
 * descriptions, and severity levels. Categories 1-30 are general security
 * categories; 31-58 are CMS/WordPress-specific.
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
        // General security categories (1-30)
        1  => ['DNS Compromise', 'DNS-Server kompromittiert oder manipuliert', 3],
        2  => ['DNS Poisoning', 'DNS-Cache-Vergiftung oder DNS-Spoofing', 4],
        3  => ['Fraud Orders', 'Betrugsversuche bei Bestellungen', 5],
        4  => ['DDoS Attack', 'Distributed Denial of Service Angriff', 9],
        5  => ['FTP Brute-Force', 'FTP-Login Brute-Force Angriff', 7],
        6  => ['Ping of Death', 'Ping of Death oder ICMP-Flood Angriff', 6],
        7  => ['Phishing', 'Phishing-Versuch oder betrügerische Weiterleitung', 8],
        8  => ['Fraud VoIP', 'VoIP-Betrug oder Telefon-Spam', 4],
        9  => ['Open Proxy', 'Offener Proxy-Server missbraucht', 5],
        10 => ['Web Spam', 'Web-Spam oder unerwünschte Inhalte', 3],
        11 => ['Email Spam', 'E-Mail-Spam-Versand', 4],
        12 => ['Blog Spam', 'Blog-Kommentar-Spam', 3],
        13 => ['VPN IP', 'VPN oder Anonymisierungsdienst', 2],
        14 => ['Port Scan', 'Port-Scanning oder Netzwerk-Aufklärung', 5],
        15 => ['Hacking', 'Allgemeiner Hacking-Versuch', 8],
        16 => ['SQL Injection', 'SQL-Injection Angriff auf Datenbank', 9],
        17 => ['Spoofing', 'IP- oder Identitäts-Spoofing', 6],
        18 => ['Brute-Force', 'Brute-Force Login-Angriff', 8],
        19 => ['Bad Web Bot', 'Bösartiger Bot oder Crawler', 4],
        20 => ['Exploited Host', 'Kompromittierter Host wird als Angriffsvektor genutzt', 7],
        21 => ['Web App Attack', 'Angriff auf Webanwendung', 7],
        22 => ['SSH Abuse', 'SSH-Missbrauch oder Brute-Force', 7],
        23 => ['IoT Targeted', 'IoT-Gerät gezielt angegriffen', 5],
        24 => ['Cryptomining', 'Unerlaubtes Kryptomining', 6],
        25 => ['Data Harvesting', 'Automatisiertes Daten-Sammeln', 5],
        26 => ['Malware Hosting', 'Server verteilt Schadsoftware', 8],
        27 => ['Command & Control', 'Botnet Command & Control Kommunikation', 9],
        28 => ['Backdoor Access', 'Versuch, eine Hintertür zu installieren', 9],
        29 => ['Ransomware', 'Ransomware-Angriff oder -Verbreitung', 10],
        30 => ['Malware Upload', 'Upload von Schadsoftware-Dateien', 9],

        // CMS/WordPress-specific categories (31-58)
        31 => ['WP Login Brute Force', 'WordPress Login Brute-Force Angriff', 8],
        32 => ['WP Admin Probe', 'WordPress Admin-Bereich Erkundung', 6],
        33 => ['WP XML-RPC Abuse', 'WordPress XML-RPC Schnittstelle missbraucht', 7],
        34 => ['WP REST API Abuse', 'WordPress REST API Missbrauch', 6],
        35 => ['WP Vulnerability Scan', 'WordPress Schwachstellen-Scan', 7],
        36 => ['WP Theme Exploit', 'WordPress Theme-Schwachstelle ausgenutzt', 8],
        37 => ['WP Core File Modification', 'WordPress Core-Datei Manipulationsversuch', 9],
        38 => ['WP Config Exposure', 'WordPress Konfigurationsdatei-Zugriff', 9],
        39 => ['WP Database Exposure', 'WordPress Datenbank-Export Zugriff', 8],
        40 => ['WP Form Spam', 'WordPress Formular-Spam', 3],
        41 => ['WP Registration Spam', 'WordPress Registrierungs-Spam', 4],
        42 => ['WP Trackback Spam', 'WordPress Trackback/Pingback Spam', 4],
        43 => ['WP File Upload Attack', 'WordPress Datei-Upload Angriff', 9],
        44 => ['Cross-Site Scripting', 'XSS-Angriff (Cross-Site Scripting)', 8],
        45 => ['Code Injection', 'Code-Injection Angriff', 9],
        46 => ['WP Core Tampering', 'WordPress Core-Datei Manipulation', 9],
        47 => ['Directory Traversal', 'Verzeichnis-Traversierung (Path Traversal)', 8],
        48 => ['File Inclusion', 'Local/Remote File Inclusion Angriff', 9],
        49 => ['Scraping', 'Automatisiertes Web-Scraping', 3],
        50 => ['Open Redirect', 'Open-Redirect Schwachstelle ausgenutzt', 6],
        51 => ['Resource Exhaustion', 'Server-Ressourcen-Erschöpfung', 7],
        52 => ['Media Library Abuse', 'Mediathek-Missbrauch oder Upload-Angriff', 6],
        53 => ['Search Spam', 'Such-Spam oder SEO-Spam Injection', 4],
        54 => ['WP Cron Abuse', 'WordPress Cron-System Missbrauch', 5],
        55 => ['User Enumeration', 'Benutzer-Aufzählung und -Erkennung', 6],
        56 => ['Version Fingerprinting', 'Software-Versions-Erkennung', 4],
        57 => ['WP Plugin Exploit', 'WordPress Plugin-Schwachstelle ausgenutzt', 8],
        58 => ['Config File Exposure', 'Konfigurationsdatei-Zugriff oder -Leak', 9],
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
