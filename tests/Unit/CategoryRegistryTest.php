<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Detection\CategoryRegistry;
use ReportedIp\Honeypot\Tests\TestCase;

/**
 * Pins the local category registry to the reportedip.com API catalogue.
 *
 * The API validates every reported category ID against its own table and
 * rejects the WHOLE report with HTTP 400 (`rest_invalid_param`) as soon as one
 * ID is unknown to it. A registry that drifts from the API therefore does two
 * kinds of damage: unknown IDs lose reports outright, and IDs whose meaning
 * differs get filed under the wrong threat (and the wrong severity) upstream.
 *
 * Source of truth: GET /wp-json/reportedip/v2/categories on reportedip.com.
 * When the API adds or renames a category, update this expectation list
 * together with the registry - never the registry alone.
 */
final class CategoryRegistryTest extends TestCase
{
    /**
     * Category ID => [API name, API severity level].
     *
     * @var array<int, array{string, int}>
     */
    private const API_CATALOGUE = [
         1 => ['DNS Compromise', 8],
         2 => ['DNS Poisoning', 9],
         3 => ['Fraud Orders', 6],
         4 => ['DDoS Attack', 9],
         5 => ['FTP Brute-Force', 7],
         6 => ['Ping of Death', 8],
         7 => ['Phishing', 9],
         8 => ['Fraud VoIP', 6],
         9 => ['Open Proxy', 5],
        10 => ['Web Spam', 4],
        11 => ['Email Spam', 4],
        12 => ['Blog Spam', 3],
        13 => ['VPN IP', 2],
        14 => ['Port Scan', 6],
        15 => ['Hacking', 8],
        16 => ['SQL Injection', 9],
        17 => ['Spoofing', 7],
        18 => ['Brute-Force', 7],
        19 => ['Bad Web Bot', 5],
        20 => ['Exploited Host', 8],
        21 => ['Web App Attack', 8],
        22 => ['SSH', 7],
        23 => ['IoT Targeted', 8],
        24 => ['Cryptocurrency Mining', 6],
        25 => ['Ransomware C&C', 10],
        26 => ['Banking Trojan', 10],
        27 => ['Mobile Malware', 8],
        28 => ['Supply Chain Attack', 10],
        29 => ['Zero-Day Exploit', 10],
        30 => ['Nation State', 10],
        31 => ['WP Login Brute Force', 7],
        32 => ['WP Admin Brute Force', 8],
        33 => ['WP XML-RPC Brute Force', 8],
        34 => ['WP REST API Abuse', 7],
        35 => ['WP Plugin Exploit', 8],
        36 => ['WP Theme Exploit', 8],
        37 => ['WP Core Exploit', 9],
        38 => ['WP Zero-Day Exploit', 10],
        39 => ['WP Comment Spam', 3],
        40 => ['WP Contact Form Spam', 4],
        41 => ['WP Registration Spam', 5],
        42 => ['WP Trackback Spam', 6],
        43 => ['WP File Upload Malware', 9],
        44 => ['WP Code Injection', 9],
        45 => ['WP Database Injection', 10],
        46 => ['WP Backdoor Installation', 10],
        47 => ['WP SEO Spam', 6],
        48 => ['WP Content Scraping', 5],
        49 => ['WP Fake SEO Bot', 6],
        50 => ['WP Redirect Hijacking', 7],
        51 => ['WP Resource Exhaustion', 7],
        52 => ['WP Media Library Abuse', 5],
        53 => ['WP Search Abuse', 4],
        54 => ['WP Cron Abuse', 6],
        55 => ['WP User Enumeration', 6],
        56 => ['WP Version Scanning', 7],
        57 => ['WP Plugin Scanning', 7],
        58 => ['WP Config Exposure', 8],
        59 => ['Honeytoken Triggered', 10],
        60 => ['Webshell Access', 9],
        61 => ['Indiscriminate Scan', 6],
        62 => ['Source Code Disclosure', 8],
        63 => ['Spider Trap', 5],
    ];

    public function testRegistryMatchesApiCatalogue(): void
    {
        $all = CategoryRegistry::getAll();

        foreach (self::API_CATALOGUE as $id => [$name, $severity]) {
            $this->t->assertTrue(
                isset($all[$id]),
                sprintf('Category %d (%s) is missing from the registry', $id, $name)
            );
            $this->t->assertEquals(
                $name,
                CategoryRegistry::getName($id),
                sprintf('Category %d name differs from the API catalogue', $id)
            );
            $this->t->assertEquals(
                $severity,
                CategoryRegistry::getSeverity($id),
                sprintf('Category %d severity differs from the API catalogue', $id)
            );
        }
    }

    public function testRegistryHasNoCategoriesUnknownToTheApi(): void
    {
        foreach (array_keys(CategoryRegistry::getAll()) as $id) {
            $this->t->assertTrue(
                isset(self::API_CATALOGUE[$id]),
                sprintf('Category %d is unknown to the API and would reject every report using it', $id)
            );
        }
    }

    public function testCategoryCountMatches(): void
    {
        $this->t->assertEquals(count(self::API_CATALOGUE), count(CategoryRegistry::getAll()));
    }

    public function testUnknownIdFallsBackGracefully(): void
    {
        $this->t->assertEquals('Unknown (999)', CategoryRegistry::getName(999));
        $this->t->assertEquals(5, CategoryRegistry::getSeverity(999));
    }
}
