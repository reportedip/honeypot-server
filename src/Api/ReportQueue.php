<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Api;

use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Persistence\Database;

/**
 * Report queue processor.
 *
 * Reads unsent log entries from the database, sends them to the
 * reportedip.de API in batches, and marks them as sent.
 */
final class ReportQueue
{
    private Database $db;
    private ReportClient $client;
    private Config $config;

    public function __construct(Database $db, ReportClient $client, Config $config)
    {
        $this->db = $db;
        $this->client = $client;
        $this->config = $config;
    }

    /**
     * Process the report queue.
     *
     * @return array{sent: int, failed: int, skipped: int, errors: string[]}
     */
    public function process(?int $batchSize = null): array
    {
        $batchSize = $batchSize ?? (int) $this->config->get('report_batch_size', 10);

        $stmt = $this->db->query(
            'SELECT * FROM honeypot_logs WHERE sent = 0 ORDER BY timestamp ASC LIMIT ?',
            [$batchSize]
        );
        $entries = $stmt->fetchAll();

        $result = ['sent' => 0, 'failed' => 0, 'skipped' => 0, 'errors' => []];

        foreach ($entries as $entry) {
            // Skip entries with empty categories
            if (empty($entry['categories'])) {
                $this->markSent([(int) $entry['id']]);
                $result['skipped']++;
                continue;
            }

            // Check rate limiting before sending
            if ($this->client->isRateLimited()) {
                $result['errors'][] = 'Rate limit reached, stopping batch';
                break;
            }

            $success = $this->client->report(
                (string) $entry['ip'],
                (string) $entry['categories'],
                (string) $entry['comment']
            );

            if ($success) {
                $this->markSent([(int) $entry['id']]);
                $result['sent']++;
            } else {
                $error = $this->client->getLastError();
                $this->markFailure((int) $entry['id'], $error);

                if ($this->client->wasPermanentlyRejected()) {
                    // 4xx (z. B. whitelisted IP): Retry kann nie gelingen —
                    // aus der Queue nehmen, sonst blockiert der Eintrag dauerhaft
                    // den Batch (ORDER BY timestamp ASC).
                    $this->markRejected((int) $entry['id']);
                    $result['skipped']++;
                } else {
                    $result['failed']++;
                }

                if ($error !== null) {
                    $errorMsg = sprintf('#%d [%s] %s', $entry['id'], $entry['ip'], $error);
                    $result['errors'][] = $errorMsg;
                }
            }
        }

        return $result;
    }

    /**
     * Get the number of unsent entries in the queue.
     */
    public function getQueueSize(): int
    {
        return (int) $this->db->query(
            'SELECT COUNT(*) FROM honeypot_logs WHERE sent = 0'
        )->fetchColumn();
    }

    /**
     * Mark entries as sent.
     *
     * @param int[] $ids
     */
    private function markSent(array $ids): void
    {
        if (empty($ids)) {
            return;
        }

        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $this->db->query(
            sprintf('UPDATE honeypot_logs SET sent = 1 WHERE id IN (%s)', $placeholders),
            $ids
        );
    }

    /**
     * Mark an entry as permanently rejected (sent = 2, same state as
     * whitelisted/skipped entries) so it leaves the queue but stays
     * distinguishable from successfully sent reports.
     */
    private function markRejected(int $id): void
    {
        $this->db->query('UPDATE honeypot_logs SET sent = 2 WHERE id = ?', [$id]);
    }

    /**
     * Persist failure metadata on a log entry so the dashboard can display recent failures.
     */
    private function markFailure(int $id, ?string $reason): void
    {
        $reason = $reason !== null ? mb_substr($reason, 0, 500) : null;
        $this->db->query(
            "UPDATE honeypot_logs
                SET failed_attempts = COALESCE(failed_attempts, 0) + 1,
                    last_failure_at = datetime('now'),
                    last_failure_reason = ?
              WHERE id = ?",
            [$reason, $id]
        );
    }
}
