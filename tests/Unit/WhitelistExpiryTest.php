<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Persistence\Whitelist;
use ReportedIp\Honeypot\Tests\TestCase;

/**
 * Covers the time-limited whitelist entries that mirror the API's own
 * whitelist (verified crawlers and the like).
 */
final class WhitelistExpiryTest extends TestCase
{
    private string $dbPath;
    private Database $db;
    private Whitelist $whitelist;

    public function setUp(): void
    {
        $this->dbPath = sys_get_temp_dir() . '/honeypot_wl_ttl_' . uniqid() . '.sqlite';
        $this->db = new Database($this->dbPath);
        $this->db->initialize();
        $this->whitelist = new Whitelist($this->db);
    }

    public function tearDown(): void
    {
        @unlink($this->dbPath);
    }

    public function testEntryWithTtlIsActiveAndCarriesAnExpiry(): void
    {
        $this->whitelist->add('66.249.65.1', 'Auto: Google: Google Bot (reportedip.com)', 7);

        $this->t->assertTrue($this->whitelist->isWhitelisted('66.249.65.1'));

        $entry = $this->findEntry('66.249.65.1');
        $this->t->assertNotNull($entry['expires_at']);
        $this->t->assertGreaterThan(time(), (int) strtotime((string) $entry['expires_at']));
    }

    public function testManualEntryStaysPermanent(): void
    {
        $this->whitelist->add('10.0.0.5', 'Office uplink');

        $entry = $this->findEntry('10.0.0.5');
        $this->t->assertNull($entry['expires_at']);
    }

    public function testExpiredEntryNoLongerCounts(): void
    {
        $this->whitelist->add('8.8.8.8', 'expired mirror', 7);
        $this->expire('8.8.8.8');

        $this->t->assertFalse($this->whitelist->isWhitelisted('8.8.8.8'));
        $this->t->assertFalse($this->whitelist->isActive('8.8.8.8'));
    }

    public function testExpiredEntryIsRefreshedOnTheNextUpstreamRejection(): void
    {
        $this->whitelist->add('8.8.4.4', 'mirror', 7);
        $this->expire('8.8.4.4');
        $this->t->assertFalse($this->whitelist->isWhitelisted('8.8.4.4'));

        $this->whitelist->add('8.8.4.4', 'mirror again', 7);

        $this->t->assertTrue($this->whitelist->isWhitelisted('8.8.4.4'));
        $this->t->assertCount(1, $this->db->query(
            'SELECT id FROM honeypot_whitelist WHERE ip_address = ?',
            ['8.8.4.4']
        )->fetchAll());
    }

    /**
     * The upstream mirror must never put an expiry on an IP the operator
     * whitelisted by hand — that entry would silently disappear a week later.
     */
    public function testMirroringDoesNotTimeLimitAManualEntry(): void
    {
        $this->whitelist->add('192.168.10.10', 'Monitoring probe');
        $this->whitelist->add('192.168.10.10', 'Auto: Google: Google Bot (reportedip.com)', 7);

        $entry = $this->findEntry('192.168.10.10');
        $this->t->assertNull($entry['expires_at']);
        $this->t->assertTrue($this->whitelist->isWhitelisted('192.168.10.10'));
    }

    public function testPurgeExpiredRemovesOnlyDeadTemporaryEntries(): void
    {
        $this->whitelist->add('1.1.1.1', 'permanent');
        $this->whitelist->add('2.2.2.2', 'live mirror', 7);
        $this->whitelist->add('3.3.3.3', 'dead mirror', 7);
        $this->expire('3.3.3.3');

        $this->t->assertEquals(1, $this->whitelist->purgeExpired());

        $remaining = array_column($this->whitelist->getAll(), 'ip_address');
        sort($remaining);
        $this->t->assertEquals(['1.1.1.1', '2.2.2.2'], $remaining);
    }

    public function testCidrEntriesKeepWorkingWithTheExpiryFilter(): void
    {
        $this->whitelist->add('66.249.64.0/19', 'Googlebot range', 7);

        $this->t->assertTrue($this->whitelist->isWhitelisted('66.249.65.77'));
        $this->t->assertFalse($this->whitelist->isWhitelisted('45.134.26.7'));
    }

    /**
     * @return array<string, mixed>
     */
    private function findEntry(string $ip): array
    {
        $row = $this->db->query(
            'SELECT * FROM honeypot_whitelist WHERE ip_address = ?',
            [$ip]
        )->fetch();

        $this->t->assertNotEmpty($row, 'whitelist entry for ' . $ip . ' is missing');

        return (array) $row;
    }

    /**
     * Backdate an entry's expiry so it counts as expired.
     */
    private function expire(string $ip): void
    {
        $this->db->query(
            "UPDATE honeypot_whitelist SET expires_at = datetime('now', '-1 hour') WHERE ip_address = ?",
            [$ip]
        );
    }
}
