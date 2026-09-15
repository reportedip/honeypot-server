<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Api\ReportClient;
use ReportedIp\Honeypot\Api\ReportQueue;
use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Persistence\Whitelist;
use ReportedIp\Honeypot\Tests\TestCase;

/**
 * Queued entries for an IP that is whitelisted by the time the queue runs must
 * leave the queue without an API call.
 *
 * This is the backlog half of the whitelist mirroring: the first rejection
 * whitelists the IP, but everything already queued for it would otherwise
 * still be sent one by one and rejected one by one.
 */
final class ReportQueueWhitelistTest extends TestCase
{
    private string $dbPath;
    private Database $db;

    public function setUp(): void
    {
        $this->dbPath = sys_get_temp_dir() . '/honeypot_queue_wl_' . uniqid() . '.sqlite';
        $this->db = new Database($this->dbPath);
        $this->db->initialize();
    }

    public function tearDown(): void
    {
        @unlink($this->dbPath);
    }

    public function testQueuedEntriesForAWhitelistedIpAreSkippedWithoutAnApiCall(): void
    {
        foreach (range(1, 3) as $i) {
            $this->queueReport('66.249.65.1');
        }
        $this->queueReport('45.134.26.7');

        (new Whitelist($this->db))->add('66.249.65.1', 'Auto: Google (reportedip.com)', 7);

        // No API key configured: report() bails out before sending, so any entry
        // that reaches it counts as failed. Skipped entries never get there.
        $queue = new ReportQueue(
            $this->db,
            new ReportClient(new Config(['api_key' => '', 'report_rate_limit' => 60])),
            new Config(['report_batch_size' => 10])
        );

        $result = $queue->process();

        $this->t->assertEquals(3, $result['skipped']);
        $this->t->assertEquals(1, $result['failed']);
        $this->t->assertEquals(0, $result['sent']);

        // The three whitelisted entries left the queue, the other one stayed.
        $this->t->assertEquals(1, $queue->getQueueSize());
        $this->t->assertEquals(0, $this->countUnsent('66.249.65.1'));
        $this->t->assertEquals(1, $this->countUnsent('45.134.26.7'));
    }

    public function testEntriesForAnExpiredWhitelistEntryAreStillProcessed(): void
    {
        $this->queueReport('8.8.8.8');

        $whitelist = new Whitelist($this->db);
        $whitelist->add('8.8.8.8', 'stale mirror', 7);
        $this->db->query(
            "UPDATE honeypot_whitelist SET expires_at = datetime('now', '-1 hour') WHERE ip_address = ?",
            ['8.8.8.8']
        );

        $queue = new ReportQueue(
            $this->db,
            new ReportClient(new Config(['api_key' => '', 'report_rate_limit' => 60])),
            new Config(['report_batch_size' => 10])
        );

        $result = $queue->process();

        $this->t->assertEquals(0, $result['skipped']);
        $this->t->assertEquals(1, $result['failed']);
    }

    private function queueReport(string $ip): void
    {
        $this->db->insert('honeypot_logs', [
            'ip'             => $ip,
            'categories'     => '18,31',
            'comment'        => 'queued detection',
            'request_uri'    => '/wp-login.php',
            'request_method' => 'POST',
            'user_agent'     => 'test/1.0',
            'sent'           => 0,
        ]);
    }

    private function countUnsent(string $ip): int
    {
        return (int) $this->db->query(
            'SELECT COUNT(*) FROM honeypot_logs WHERE ip = ? AND sent = 0',
            [$ip]
        )->fetchColumn();
    }
}
