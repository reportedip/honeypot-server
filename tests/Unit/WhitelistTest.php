<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Persistence\Whitelist;
use ReportedIp\Honeypot\Tests\TestCase;

final class WhitelistTest extends TestCase
{
    private string $dbPath;
    private Database $db;
    private Whitelist $whitelist;

    public function setUp(): void
    {
        $this->dbPath = sys_get_temp_dir() . '/honeypot_wl_test_' . uniqid() . '.sqlite';
        $this->db = new Database($this->dbPath);
        $this->db->initialize();
        $this->whitelist = new Whitelist($this->db);
    }

    public function tearDown(): void
    {
        @unlink($this->dbPath);
    }

    public function testAddAndIsWhitelisted(): void
    {
        $this->whitelist->add('10.0.0.1', 'Test IP');
        $this->t->assertTrue($this->whitelist->isWhitelisted('10.0.0.1'));
    }

    public function testIsWhitelistedReturnsFalseForUnknown(): void
    {
        $this->t->assertFalse($this->whitelist->isWhitelisted('99.99.99.99'));
    }

    public function testRemove(): void
    {
        $this->whitelist->add('10.0.0.2', 'To remove');
        $this->t->assertTrue($this->whitelist->isWhitelisted('10.0.0.2'));

        $this->whitelist->remove('10.0.0.2');
        $this->t->assertFalse($this->whitelist->isWhitelisted('10.0.0.2'));
    }

    public function testAddReactivatesRemovedEntry(): void
    {
        $this->whitelist->add('10.0.0.3', 'First add');
        $this->whitelist->remove('10.0.0.3');
        $this->t->assertFalse($this->whitelist->isWhitelisted('10.0.0.3'));

        $this->whitelist->add('10.0.0.3', 'Re-added');
        $this->t->assertTrue($this->whitelist->isWhitelisted('10.0.0.3'));
    }

    public function testCidrWhitelisting(): void
    {
        $this->whitelist->add('192.168.1.0/24', 'Local network');
        $this->t->assertTrue($this->whitelist->isWhitelisted('192.168.1.50'));
        $this->t->assertTrue($this->whitelist->isWhitelisted('192.168.1.254'));
        $this->t->assertFalse($this->whitelist->isWhitelisted('192.168.2.1'));
    }

    public function testGetAll(): void
    {
        $this->whitelist->add('10.0.0.10', 'Entry 1');
        $this->whitelist->add('10.0.0.11', 'Entry 2');
        $all = $this->whitelist->getAll();
        $this->t->assertGreaterThanOrEqual(2, count($all));
    }

    public function testIsActive(): void
    {
        $this->whitelist->add('10.0.0.20', 'Active test');
        $this->t->assertTrue($this->whitelist->isActive('10.0.0.20'));

        $this->whitelist->remove('10.0.0.20');
        $this->t->assertFalse($this->whitelist->isActive('10.0.0.20'));
    }

    public function testIsActiveReturnsFalseForUnknownIp(): void
    {
        $this->t->assertFalse($this->whitelist->isActive('255.255.255.255'));
    }
}
