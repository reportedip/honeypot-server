<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Api\ReportClient;
use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Tests\TestCase;

final class ReportClientTest extends TestCase
{
    public function testIsRateLimitedReturnsFalseInitially(): void
    {
        $config = new Config(['report_rate_limit' => 60]);
        $client = new ReportClient($config);
        $this->t->assertFalse($client->isRateLimited());
    }

    public function testIsRateLimitedWithZeroLimit(): void
    {
        $config = new Config(['report_rate_limit' => 0]);
        $client = new ReportClient($config);
        // With limit=0, any count >= 0 means rate limited
        $this->t->assertTrue($client->isRateLimited());
    }

    public function testReportReturnsFalseWithEmptyApiKey(): void
    {
        $config = new Config(['api_key' => '', 'report_rate_limit' => 60]);
        $client = new ReportClient($config);
        $result = $client->report('1.2.3.4', '16', 'test');
        $this->t->assertFalse($result);
    }

    public function testReportReturnsFalseWhenRateLimited(): void
    {
        $config = new Config(['api_key' => 'test_key', 'report_rate_limit' => 0]);
        $client = new ReportClient($config);
        $result = $client->report('1.2.3.4', '16', 'test');
        $this->t->assertFalse($result);
    }

    public function testDefaultRateLimitIs60(): void
    {
        $config = new Config([]);
        $client = new ReportClient($config);
        // Default rate_limit_per_ip should be 60, so not rate limited initially
        $this->t->assertFalse($client->isRateLimited());
    }

    public function testPermanentRejectionCodes(): void
    {
        // 4xx (außer 429/408/499) = permanente Ablehnung, kein Retry sinnvoll
        $this->t->assertTrue(ReportClient::isPermanentRejectionCode(400));
        $this->t->assertTrue(ReportClient::isPermanentRejectionCode(403));
        $this->t->assertTrue(ReportClient::isPermanentRejectionCode(422));
        // 429 = Rate Limit, temporär
        $this->t->assertFalse(ReportClient::isPermanentRejectionCode(429));
        // 408 Request Timeout / 499 Client Closed (Überlast) = temporär, kein permanenter Reject
        $this->t->assertFalse(ReportClient::isPermanentRejectionCode(408));
        $this->t->assertFalse(ReportClient::isPermanentRejectionCode(499));
        // 5xx = Serverfehler, temporär
        $this->t->assertFalse(ReportClient::isPermanentRejectionCode(500));
        $this->t->assertFalse(ReportClient::isPermanentRejectionCode(503));
        // Erfolg / Verbindungsfehler
        $this->t->assertFalse(ReportClient::isPermanentRejectionCode(200));
        $this->t->assertFalse(ReportClient::isPermanentRejectionCode(0));
    }

    public function testTransientFailureCodes(): void
    {
        // Überlast-/Backoff-würdige Codes (exakt die aus dem Retry-Sturm)
        $this->t->assertTrue(ReportClient::isTransientFailureCode(429));
        $this->t->assertTrue(ReportClient::isTransientFailureCode(408));
        $this->t->assertTrue(ReportClient::isTransientFailureCode(499));
        $this->t->assertTrue(ReportClient::isTransientFailureCode(500));
        $this->t->assertTrue(ReportClient::isTransientFailureCode(502));
        $this->t->assertTrue(ReportClient::isTransientFailureCode(503));
        $this->t->assertTrue(ReportClient::isTransientFailureCode(504));
        // cURL-/Verbindungsfehler (Timeout, Connection refused)
        $this->t->assertTrue(ReportClient::isTransientFailureCode(0));
        // Erfolg und permanente Ablehnungen sind NICHT transient
        $this->t->assertFalse(ReportClient::isTransientFailureCode(200));
        $this->t->assertFalse(ReportClient::isTransientFailureCode(400));
        $this->t->assertFalse(ReportClient::isTransientFailureCode(403));
    }

    public function testPersistedBackoffIsLoadedAndBlocksReports(): void
    {
        $dir = sys_get_temp_dir() . '/rip_backoff_' . uniqid('', true);
        mkdir($dir, 0777, true);

        try {
            // Aktiver Backoff (in der Zukunft) wird aus der Datei geladen
            file_put_contents($dir . '/report_backoff.json', json_encode([
                'backoff_until'   => time() + 120,
                'current_backoff' => 40,
            ]));

            $config = new Config([
                'api_key'           => 'test_key',
                'report_rate_limit' => 60,
                'data_dir'          => $dir,
            ]);
            $client = new ReportClient($config);

            $this->t->assertTrue($client->isBackedOff());

            // report() darf nicht senden, solange der Backoff aktiv ist
            $result = $client->report('1.2.3.4', '16', 'test');
            $this->t->assertFalse($result);
            $this->t->assertTrue(str_contains((string) $client->getLastError(), 'Backoff'));
        } finally {
            @unlink($dir . '/report_backoff.json');
            @rmdir($dir);
        }
    }

    public function testPersistedRateLimitIsLoadedAcrossInstances(): void
    {
        $dir = sys_get_temp_dir() . '/rip_rl_' . uniqid('', true);
        mkdir($dir, 0777, true);

        try {
            // 60 frische Timestamps innerhalb des 60s-Fensters
            $now = time();
            $timestamps = [];
            for ($i = 0; $i < 60; $i++) {
                $timestamps[] = $now;
            }
            file_put_contents(
                $dir . '/report_ratelimit.json',
                json_encode(['timestamps' => $timestamps])
            );

            // Frischer Client (wie ein neuer Web-Cron-Request) sieht das Cap
            $config = new Config(['report_rate_limit' => 60, 'data_dir' => $dir]);
            $client = new ReportClient($config);

            $this->t->assertTrue($client->isRateLimited());
        } finally {
            @unlink($dir . '/report_ratelimit.json');
            @rmdir($dir);
        }
    }

    public function testPersistedRateLimitPrunesExpiredTimestamps(): void
    {
        $dir = sys_get_temp_dir() . '/rip_rl_' . uniqid('', true);
        mkdir($dir, 0777, true);

        try {
            // Alle Timestamps älter als 60s → fallen aus dem Fenster
            $old = time() - 120;
            file_put_contents(
                $dir . '/report_ratelimit.json',
                json_encode(['timestamps' => array_fill(0, 100, $old)])
            );

            $config = new Config(['report_rate_limit' => 60, 'data_dir' => $dir]);
            $client = new ReportClient($config);

            $this->t->assertFalse($client->isRateLimited());
        } finally {
            @unlink($dir . '/report_ratelimit.json');
            @rmdir($dir);
        }
    }

    public function testExpiredBackoffIsNotActive(): void
    {
        $dir = sys_get_temp_dir() . '/rip_backoff_' . uniqid('', true);
        mkdir($dir, 0777, true);

        try {
            // Abgelaufener Backoff (in der Vergangenheit) blockiert nicht mehr
            file_put_contents($dir . '/report_backoff.json', json_encode([
                'backoff_until'   => time() - 10,
                'current_backoff' => 40,
            ]));

            $config = new Config(['api_key' => 'test_key', 'data_dir' => $dir]);
            $client = new ReportClient($config);

            $this->t->assertFalse($client->isBackedOff());
        } finally {
            @unlink($dir . '/report_backoff.json');
            @rmdir($dir);
        }
    }

    public function testUserAgentContainsCurrentVersion(): void
    {
        $versionFile = dirname(__DIR__, 2) . '/VERSION';
        $version = trim((string) file_get_contents($versionFile));

        $userAgent = ReportClient::getUserAgent();
        $this->t->assertEquals('reportedip-honeypot-server/' . $version, $userAgent);
        // Hartcodierte Versionen dürfen nicht mehr vorkommen
        $this->t->assertTrue($version !== '', 'VERSION file must not be empty');
    }

    public function testDetectsInvalidCategoryRejection(): void
    {
        $body = '{"code":"rest_invalid_param","message":"Invalid parameter(s): categories",'
              . '"data":{"status":400,"params":{"categories":"categories is not of type string."}}}';

        // Genau die Antwort, die eine API ohne die Honeypot-Kategorien liefert
        $this->t->assertTrue(ReportClient::isInvalidCategoryRejection(400, $body));
        // Anderer Parameter -> kein Kategorie-Problem, kein Retry
        $this->t->assertFalse(ReportClient::isInvalidCategoryRejection(
            400,
            '{"code":"rest_invalid_param","message":"Invalid parameter(s): ip"}'
        ));
        // Anderer Fehlercode (z. B. ungültiger Key) -> kein Retry
        $this->t->assertFalse(ReportClient::isInvalidCategoryRejection(
            403,
            '{"code":"rest_forbidden","message":"Invalid API key"}'
        ));
        // Erfolg
        $this->t->assertFalse(ReportClient::isInvalidCategoryRejection(200, '{"success":true}'));
    }

    public function testStripUnsupportedCategoriesKeepsCoreRange(): void
    {
        // Kategorien jenseits der Kern-Range fliegen raus, Reihenfolge bleibt
        $this->t->assertEquals('14,15,19,21,49', ReportClient::stripUnsupportedCategories('14,15,19,21,49,61'));
        $this->t->assertEquals('15,18,46', ReportClient::stripUnsupportedCategories('15,18,46,59'));
        // Kern-Kategorien bleiben unverändert
        $this->t->assertEquals('16,18', ReportClient::stripUnsupportedCategories('16,18'));
        // Whitespace und leere Felder werden normalisiert
        $this->t->assertEquals('16,18', ReportClient::stripUnsupportedCategories(' 16 , ,18 '));
        // Ohne verbleibende Kategorie bleibt nichts uebrig -> kein Retry moeglich
        $this->t->assertEquals('', ReportClient::stripUnsupportedCategories('59,63'));
        $this->t->assertEquals('', ReportClient::stripUnsupportedCategories(''));
        // Unsinnige Werte werden verworfen, nicht durchgereicht
        $this->t->assertEquals('', ReportClient::stripUnsupportedCategories('0,-3,abc,999'));
    }

    public function testWasPermanentlyRejectedFalseWithoutRequest(): void
    {
        $config = new Config(['api_key' => '', 'report_rate_limit' => 60]);
        $client = new ReportClient($config);
        // Lokaler Fehler (kein API-Key) ist keine permanente API-Ablehnung
        $client->report('1.2.3.4', '16', 'test');
        $this->t->assertFalse($client->wasPermanentlyRejected());
    }
}
