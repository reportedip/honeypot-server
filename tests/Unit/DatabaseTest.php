<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Tests\TestCase;

final class DatabaseTest extends TestCase
{
    private string $dbPath;
    private Database $db;

    public function setUp(): void
    {
        $this->dbPath = sys_get_temp_dir() . '/honeypot_test_' . uniqid() . '.sqlite';
        $this->db = new Database($this->dbPath);
    }

    public function tearDown(): void
    {
        @unlink($this->dbPath);
    }

    public function testGetConnectionReturnsPdo(): void
    {
        $pdo = $this->db->getConnection();
        $this->t->assertInstanceOf(\PDO::class, $pdo);
    }

    public function testGetConnectionReturnsSameInstance(): void
    {
        $pdo1 = $this->db->getConnection();
        $pdo2 = $this->db->getConnection();
        $this->t->assertTrue($pdo1 === $pdo2, 'Should return the same PDO instance');
    }

    public function testInitializeCreatesLogsTable(): void
    {
        $this->db->initialize();
        $pdo = $this->db->getConnection();
        $tables = $pdo->query("SELECT name FROM sqlite_master WHERE type='table'")->fetchAll();
        $tableNames = array_column($tables, 'name');
        $this->t->assertTrue(in_array('honeypot_logs', $tableNames, true), 'honeypot_logs table should exist');
    }

    public function testInitializeCreatesWhitelistTable(): void
    {
        $this->db->initialize();
        $pdo = $this->db->getConnection();
        $tables = $pdo->query("SELECT name FROM sqlite_master WHERE type='table'")->fetchAll();
        $tableNames = array_column($tables, 'name');
        $this->t->assertTrue(in_array('honeypot_whitelist', $tableNames, true), 'honeypot_whitelist table should exist');
    }

    public function testInitializeIsIdempotent(): void
    {
        $this->db->initialize();
        $this->db->initialize(); // Should not throw
        $pdo = $this->db->getConnection();
        $count = (int) $pdo->query("SELECT COUNT(*) FROM honeypot_logs")->fetchColumn();
        $this->t->assertEquals(0, $count);
    }

    public function testInsertReturnsId(): void
    {
        $this->db->initialize();
        $id = $this->db->insert('honeypot_logs', [
            'ip'         => '1.2.3.4',
            'categories' => '16,45',
            'comment'    => 'test entry',
        ]);
        $this->t->assertGreaterThan(0, $id);
    }

    public function testQueryRetrievesInsertedData(): void
    {
        $this->db->initialize();
        $this->db->insert('honeypot_logs', [
            'ip'         => '10.0.0.1',
            'categories' => '18',
            'comment'    => 'brute force test',
        ]);

        $stmt = $this->db->query('SELECT * FROM honeypot_logs WHERE ip = ?', ['10.0.0.1']);
        $rows = $stmt->fetchAll();
        $this->t->assertCount(1, $rows);
        $this->t->assertEquals('10.0.0.1', $rows[0]['ip']);
        $this->t->assertEquals('brute force test', $rows[0]['comment']);
    }

    public function testMultipleInserts(): void
    {
        $this->db->initialize();
        $id1 = $this->db->insert('honeypot_logs', ['ip' => '1.1.1.1', 'categories' => '15', 'comment' => 'first']);
        $id2 = $this->db->insert('honeypot_logs', ['ip' => '2.2.2.2', 'categories' => '16', 'comment' => 'second']);
        $this->t->assertGreaterThan($id1, $id2);

        $count = (int) $this->db->getConnection()->query("SELECT COUNT(*) FROM honeypot_logs")->fetchColumn();
        $this->t->assertEquals(2, $count);
    }
}
