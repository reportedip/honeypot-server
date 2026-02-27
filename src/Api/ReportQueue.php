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
                $result['failed']++;
                $error = $this->client->getLastError();
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
}
