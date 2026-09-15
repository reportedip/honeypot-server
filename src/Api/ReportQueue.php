<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Api;

use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Persistence\Whitelist;

/**
 * Report queue processor.
 *
 * Reads unsent log entries from the database, sends them to the
 * reportedip.com API in batches, and marks them as sent.
 */
final class ReportQueue
{
    /**
     * Days an IP stays on the local whitelist after the API rejected a report
     * for it as whitelisted. Long enough to stop the pointless retries, short
     * enough that an IP losing its upstream whitelisting is picked up again.
     */
    private const UPSTREAM_WHITELIST_TTL_DAYS = 7;

    private Database $db;
    private ReportClient $client;
    private Config $config;
    private Whitelist $whitelist;

    public function __construct(Database $db, ReportClient $client, Config $config)
    {
        $this->db = $db;
        $this->client = $client;
        $this->config = $config;
        $this->whitelist = new Whitelist($db);
    }

    /**
     * Process the report queue.
     *
     * @return array{sent: int, failed: int, skipped: int, whitelisted: int, errors: string[]}
     */
    public function process(?int $batchSize = null): array
    {
        $batchSize = $batchSize ?? (int) $this->config->get('report_batch_size', 10);

        $stmt = $this->db->query(
            'SELECT * FROM honeypot_logs WHERE sent = 0 ORDER BY timestamp ASC LIMIT ?',
            [$batchSize]
        );
        $entries = $stmt->fetchAll();

        $result = ['sent' => 0, 'failed' => 0, 'skipped' => 0, 'whitelisted' => 0, 'errors' => []];

        foreach ($entries as $entry) {
            // Skip entries with empty categories
            if (empty($entry['categories'])) {
                $this->markSent([(int) $entry['id']]);
                $result['skipped']++;
                continue;
            }

            // The IP may have landed on the whitelist after this entry was
            // queued — either mirrored from the API's own verdict or added by
            // the operator. Sending it would just earn another rejection.
            if ($this->whitelist->isWhitelisted((string) $entry['ip'])) {
                $this->markRejected((int) $entry['id']);
                $result['skipped']++;
                continue;
            }

            // Stop the batch while an API backoff is active — otherwise every
            // remaining entry would run through report(), fail, and inflate its
            // failed_attempts counter without anything actually being sent.
            if ($this->client->isBackedOff()) {
                $result['errors'][] = 'Backoff active, stopping batch';
                break;
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
                    // 4xx (e.g. whitelisted IP): a retry can never succeed —
                    // drop it from the queue, otherwise the entry blocks the
                    // batch forever (ORDER BY timestamp ASC).
                    $this->markRejected((int) $entry['id']);
                    $result['skipped']++;

                    // The API rejected this IP as whitelisted (verified crawlers
                    // and the like). Mirror that verdict locally for a while so
                    // the honeypot stops detecting, queueing and sending reports
                    // for an IP the API will keep refusing.
                    if ($this->client->wasWhitelistedUpstream()
                        && $this->mirrorUpstreamWhitelist((string) $entry['ip'])) {
                        $result['whitelisted']++;
                    }
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
     * Copy the API's whitelist verdict into the local whitelist.
     *
     * Only exact IPs are mirrored — the API reports the verdict for the single
     * address that was submitted, not for the range it may come from.
     *
     * @return bool True when the IP was written to the whitelist.
     */
    private function mirrorUpstreamWhitelist(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        $this->whitelist->add(
            $ip,
            sprintf('Auto: %s (reportedip.com)', $this->client->getWhitelistReason()),
            self::UPSTREAM_WHITELIST_TTL_DAYS
        );

        return true;
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
