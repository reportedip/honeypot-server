<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Persistence\Whitelist;
use ReportedIp\Honeypot\Tests\TestCase;

/**
 * Upgrading an existing installation must add honeypot_whitelist.expires_at
 * without touching the entries that are already there — every deployed
 * honeypot carries the pre-expiry schema.
 */
final class WhitelistMigrationTest extends TestCase
{
    private string $dbPath;

    public function setUp(): void
    {
        $this->dbPath = sys_get_temp_dir() . '/honeypot_wl_migrate_' . uniqid() . '.sqlite';

        // Schema as shipped before the expiry column existed.
        $pdo = new \PDO('sqlite:' . $this->dbPath);
        $pdo->exec('
            CREATE TABLE honeypot_whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE,
                description TEXT,
                added_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_active INTEGER DEFAULT 1
            )
        ');
        $pdo->exec("INSERT INTO honeypot_whitelist (ip_address, description) VALUES ('10.0.0.1', 'Office')");
        $pdo = null;
    }

    public function tearDown(): void
    {
        @unlink($this->dbPath);
    }

    public function testInitializeAddsTheExpiryColumnAndKeepsExistingEntries(): void
    {
        $db = new Database($this->dbPath);
        $db->initialize();

        $columns = array_column(
            $db->query('PRAGMA table_info(honeypot_whitelist)')->fetchAll(),
            'name'
        );
        $this->t->assertTrue(in_array('expires_at', $columns, true), 'expires_at column missing');

        $whitelist = new Whitelist($db);

        // The pre-existing entry has no expiry and must stay permanently active.
        $this->t->assertTrue($whitelist->isWhitelisted('10.0.0.1'));
        $this->t->assertEquals(0, $whitelist->purgeExpired());

        // And the new time-limited path works on the migrated table.
        $whitelist->add('66.249.65.1', 'Auto: Google (reportedip.com)', 7);
        $this->t->assertTrue($whitelist->isWhitelisted('66.249.65.1'));
    }

    public function testInitializeIsIdempotent(): void
    {
        $db = new Database($this->dbPath);
        $db->initialize();
        $db->initialize();

        $this->t->assertTrue((new Whitelist($db))->isWhitelisted('10.0.0.1'));
    }
}
