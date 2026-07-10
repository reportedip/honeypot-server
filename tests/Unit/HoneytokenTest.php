<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Detection\Honeytoken;
use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Tests\TestCase;

final class HoneytokenTest extends TestCase
{
    private string $dbPath;
    private Database $db;
    private Honeytoken $honeytoken;

    public function setUp(): void
    {
        $this->dbPath = sys_get_temp_dir() . '/honeypot_token_test_' . uniqid() . '.sqlite';
        $this->db = new Database($this->dbPath);
        $this->db->initialize();
        $this->honeytoken = new Honeytoken($this->db);
    }

    public function tearDown(): void
    {
        @unlink($this->dbPath);
    }

    public function testIssuedTokenCarriesMarker(): void
    {
        $token = $this->honeytoken->issue('db_password', '9.9.9.9', '/.env');
        $this->t->assertStringContains(Honeytoken::MARKER, $token);
    }

    public function testIssueIsStablePerIpAndType(): void
    {
        $a = $this->honeytoken->issue('db_password', '9.9.9.9', '/.env');
        $b = $this->honeytoken->issue('db_password', '9.9.9.9', '/.env');
        $this->t->assertEquals($a, $b);
    }

    public function testDifferentTypesGetDifferentTokens(): void
    {
        $a = $this->honeytoken->issue('db_password', '9.9.9.9', '/.env');
        $b = $this->honeytoken->issue('aws_secret', '9.9.9.9', '/.env');
        $this->t->assertNotEquals($a, $b);
    }

    public function testDetectReuseFlagsReplayedToken(): void
    {
        $token = $this->honeytoken->issue('db_password', '10.0.0.1', '/.env');
        $haystack = 'log=admin&pwd=' . $token;
        $result = $this->honeytoken->detectReuse($haystack, '10.0.0.2');
        $this->t->assertNotNull($result);
        $this->t->assertEquals(100, $result->getScore());
        $this->t->assertTrue(in_array(59, $result->getCategories(), true));
    }

    public function testDetectReuseIgnoresCleanRequest(): void
    {
        $this->honeytoken->issue('db_password', '10.0.0.1', '/.env');
        $result = $this->honeytoken->detectReuse('log=admin&pwd=hunter2', '10.0.0.2');
        $this->t->assertNull($result);
    }

    public function testDetectReuseIgnoresUnknownMarkerValue(): void
    {
        // A value that looks shaped like a token but was never issued.
        $fake = Honeytoken::MARKER . str_repeat('a', 16);
        $result = $this->honeytoken->detectReuse('pwd=' . $fake, '10.0.0.2');
        $this->t->assertNull($result);
    }
}
