<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Detection\DetectionResult;
use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Persistence\Logger;
use ReportedIp\Honeypot\Tests\TestCase;

final class LoggerTest extends TestCase
{
    private string $dbPath;
    private Database $db;
    private Logger $logger;

    public function setUp(): void
    {
        $this->dbPath = sys_get_temp_dir() . '/honeypot_logger_test_' . uniqid() . '.sqlite';
        $this->db = new Database($this->dbPath);
        $this->db->initialize();
        $config = new Config(['rate_limit_per_ip' => 100]);
        $this->logger = new Logger($this->db, $config);
    }

    public function tearDown(): void
    {
        @unlink($this->dbPath);
    }

    public function testLogInsertsEntry(): void
    {
        $request = $this->createRequest([
            'uri'     => '/wp-login.php',
            'method'  => 'POST',
            'ip'      => '5.5.5.5',
            'headers' => ['User-Agent' => 'TestBot'],
        ]);
        $results = [new DetectionResult([18, 31], 'Brute force test', 80, 'BruteForce')];
        $this->logger->log($request, $results);

        $logs = $this->logger->getRecentLogs(10);
        $this->t->assertCount(1, $logs);
        $this->t->assertEquals('5.5.5.5', $logs[0]['ip']);
        $this->t->assertContains('18', $logs[0]['categories']);
    }

    public function testGetRecentLogsReturnsCorrectOrder(): void
    {
        for ($i = 1; $i <= 3; $i++) {
            $request = $this->createRequest(['ip' => "1.1.1.{$i}", 'uri' => "/test{$i}"]);
            $results = [new DetectionResult([15], "test {$i}", 50, 'Test')];
            $this->logger->log($request, $results);
        }

        $logs = $this->logger->getRecentLogs(10);
        $this->t->assertCount(3, $logs);
    }

    public function testGetRecentLogsRespectsLimit(): void
    {
        for ($i = 1; $i <= 5; $i++) {
            $request = $this->createRequest(['ip' => "2.2.2.{$i}"]);
            $results = [new DetectionResult([15], "entry {$i}", 50, 'Test')];
            $this->logger->log($request, $results);
        }

        $logs = $this->logger->getRecentLogs(3);
        $this->t->assertCount(3, $logs);
    }

    public function testGetStats(): void
    {
        $request = $this->createRequest(['ip' => '3.3.3.3']);
        $results = [new DetectionResult([16], 'sql injection', 90, 'SQLi')];
        $this->logger->log($request, $results);

        $stats = $this->logger->getStats();
        $this->t->assertArrayHasKey('total', $stats);
        $this->t->assertArrayHasKey('today', $stats);
        $this->t->assertArrayHasKey('unique_ips', $stats);
        $this->t->assertArrayHasKey('pending', $stats);
        $this->t->assertArrayHasKey('top_categories', $stats);
        $this->t->assertArrayHasKey('top_ips', $stats);
        $this->t->assertGreaterThanOrEqual(1, $stats['total']);
    }

    public function testGetUnsent(): void
    {
        $request = $this->createRequest(['ip' => '4.4.4.4']);
        $results = [new DetectionResult([21], 'probe', 50, 'Probe')];
        $this->logger->log($request, $results);

        $unsent = $this->logger->getUnsent();
        $this->t->assertGreaterThanOrEqual(1, count($unsent));
        $this->t->assertEquals(0, (int) $unsent[0]['sent']);
    }

    public function testMarkSent(): void
    {
        $request = $this->createRequest(['ip' => '6.6.6.6']);
        $results = [new DetectionResult([15], 'test', 50, 'Test')];
        $this->logger->log($request, $results);

        $unsent = $this->logger->getUnsent();
        $ids = array_column($unsent, 'id');
        $this->logger->markSent(array_map('intval', $ids));

        $stillUnsent = $this->logger->getUnsent();
        $unsentIps = array_column($stillUnsent, 'ip');
        $this->t->assertFalse(in_array('6.6.6.6', $unsentIps, true));
    }

    public function testLogMergesCategories(): void
    {
        $request = $this->createRequest(['ip' => '7.7.7.7']);
        $results = [
            new DetectionResult([16, 45], 'sqli', 90, 'SQLi'),
            new DetectionResult([18], 'brute', 80, 'Brute'),
        ];
        $this->logger->log($request, $results);

        $logs = $this->logger->getRecentLogs(1);
        $categories = $logs[0]['categories'];
        $this->t->assertContains('16', $categories);
        $this->t->assertContains('18', $categories);
    }
}
