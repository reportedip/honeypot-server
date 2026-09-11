<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Admin\LogViewer;
use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Detection\DetectionResult;
use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Persistence\Logger;
use ReportedIp\Honeypot\Tests\TestCase;

final class LogViewerTest extends TestCase
{
    private string $dbPath;
    private Database $db;
    private Logger $logger;
    private LogViewer $viewer;

    public function setUp(): void
    {
        $this->dbPath = sys_get_temp_dir() . '/honeypot_logviewer_test_' . uniqid() . '.sqlite';
        $this->db = new Database($this->dbPath);
        $this->db->initialize();
        $config = new Config(['rate_limit_per_ip' => 100]);
        $this->logger = new Logger($this->db, $config);
        $this->viewer = new LogViewer($this->db, $this->logger);

        $req1 = $this->createRequest(['ip' => '1.1.1.1', 'uri' => '/?id=1']);
        $this->logger->log($req1, [new DetectionResult([16], 'SQLi', 90, 'SqlInjection')]);

        $req2 = $this->createRequest(['ip' => '2.2.2.2', 'uri' => '/scan']);
        $this->logger->log($req2, [new DetectionResult([14], 'PortScan', 60, 'PortScan')]);

        $req3 = $this->createRequest(['ip' => '3.3.3.3', 'uri' => '/comment']);
        $this->logger->log($req3, [new DetectionResult([12], 'Spam', 30, 'BlogSpam')]);
    }

    public function tearDown(): void
    {
        @unlink($this->dbPath);
    }

    public function testGetPageReturnsAllByDefault(): void
    {
        $page = $this->viewer->getPage(1);
        $this->t->assertEquals(3, $page['total']);
    }

    public function testFilterByCategory(): void
    {
        $page = $this->viewer->getPage(1, ['category' => '16']);
        $this->t->assertEquals(1, $page['total']);
        $this->t->assertEquals('1.1.1.1', $page['logs'][0]['ip']);
    }

    public function testFilterBySeverityCritical(): void
    {
        $page = $this->viewer->getPage(1, ['severity' => 'critical']);
        $this->t->assertEquals(1, $page['total']);
        $this->t->assertEquals('1.1.1.1', $page['logs'][0]['ip']);
    }

    public function testFilterBySeverityHigh(): void
    {
        $page = $this->viewer->getPage(1, ['severity' => 'high']);
        $this->t->assertEquals(1, $page['total']);
        $this->t->assertEquals('2.2.2.2', $page['logs'][0]['ip']);
    }

    public function testFilterBySeverityMedium(): void
    {
        $page = $this->viewer->getPage(1, ['severity' => 'medium']);
        $this->t->assertEquals(1, $page['total']);
        $this->t->assertEquals('3.3.3.3', $page['logs'][0]['ip']);
    }

    public function testFilterByUnknownSeverityReturnsEmpty(): void
    {
        $page = $this->viewer->getPage(1, ['severity' => 'nonexistent']);
        $this->t->assertEquals(0, $page['total']);
    }
}
