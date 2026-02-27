<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Api;

use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Persistence\Logger;
use ReportedIp\Honeypot\Persistence\VisitorLogger;

/**
 * Web-based cron processor for automatic queue processing.
 *
 * Processes a micro-batch of pending reports after each page visit,
 * eliminating the need for an external cron job on shared hosting.
 */
final class WebCronProcessor
{
    private const WEB_BATCH_SIZE = 2;
    private const CLEANUP_INTERVAL_SECONDS = 3600;

    private Database $db;
    private Config $config;

    public function __construct(Database $db, Config $config)
    {
        $this->db = $db;
        $this->config = $config;
    }

    /**
     * Process a micro-batch of the report queue.
     *
     * Called after the HTTP response has been flushed to the client.
     * Skips processing if no API key is configured or the queue is empty.
     */
    public function process(): void
    {
        $apiKey = (string) $this->config->get('api_key', '');
        if ($apiKey === '') {
            return;
        }

        $pending = $this->getPendingCount();

        if ($pending === 0) {
            $this->maybeCleanup();
            return;
        }

        $client = new ReportClient($this->config);
        $queue = new ReportQueue($this->db, $client, $this->config);

        $result = $queue->process(self::WEB_BATCH_SIZE);
        $remaining = $queue->getQueueSize();

        $this->maybeCleanup();
        $this->saveCronStatus($result, $remaining);
    }

    /**
     * Get the number of unsent entries in the queue.
     */
    private function getPendingCount(): int
    {
        return (int) $this->db->query(
            'SELECT COUNT(*) FROM honeypot_logs WHERE sent = 0'
        )->fetchColumn();
    }

    /**
     * Run cleanup if more than one hour has passed since the last cleanup.
     */
    private function maybeCleanup(): void
    {
        $statusFile = $this->getStatusFilePath();
        if ($statusFile === null) {
            return;
        }

        $lastCleanupTs = 0;
        if (file_exists($statusFile)) {
            $data = @json_decode((string) file_get_contents($statusFile), true);
            if (is_array($data)) {
                $lastCleanupTs = (int) ($data['last_cleanup_ts'] ?? 0);
            }
        }

        if ((time() - $lastCleanupTs) < self::CLEANUP_INTERVAL_SECONDS) {
            return;
        }

        $retentionDays = (int) $this->config->get('log_retention_days', 90);

        $logger = new Logger($this->db, $this->config);
        $logger->cleanup($retentionDays);

        $visitorLogger = new VisitorLogger($this->db);
        $visitorLogger->cleanup($retentionDays);

        // Update last_cleanup_ts in status file
        $existing = [];
        if (file_exists($statusFile)) {
            $existing = @json_decode((string) file_get_contents($statusFile), true) ?: [];
        }
        $existing['last_cleanup_ts'] = time();
        @file_put_contents($statusFile, json_encode($existing, JSON_PRETTY_PRINT), LOCK_EX);
    }

    /**
     * Save cron run status to a JSON file for the admin dashboard.
     *
     * @param array{sent: int, failed: int, skipped: int, errors: string[]} $result
     */
    private function saveCronStatus(array $result, int $remaining): void
    {
        $statusFile = $this->getStatusFilePath();
        if ($statusFile === null) {
            return;
        }

        $existing = [];
        if (file_exists($statusFile)) {
            $existing = @json_decode((string) file_get_contents($statusFile), true) ?: [];
        }

        $existing['last_run'] = date('Y-m-d H:i:s');
        $existing['queue_mode'] = 'web';
        $existing['last_result'] = [
            'sent'       => $result['sent'],
            'failed'     => $result['failed'],
            'skipped'    => $result['skipped'],
            'remaining'  => $remaining,
            'cleaned'    => 0,
            'had_errors' => !empty($result['errors']),
        ];

        if (!isset($existing['history'])) {
            $existing['history'] = [];
        }
        array_unshift($existing['history'], [
            'time'   => date('Y-m-d H:i:s'),
            'sent'   => $result['sent'],
            'failed' => $result['failed'],
        ]);
        $existing['history'] = array_slice($existing['history'], 0, 24);

        $existing['total_sent'] = ($existing['total_sent'] ?? 0) + $result['sent'];
        $existing['total_failed'] = ($existing['total_failed'] ?? 0) + $result['failed'];
        $existing['runs_count'] = ($existing['runs_count'] ?? 0) + 1;

        if (!isset($existing['last_cleanup_ts'])) {
            $existing['last_cleanup_ts'] = 0;
        }

        @file_put_contents($statusFile, json_encode($existing, JSON_PRETTY_PRINT), LOCK_EX);
    }

    /**
     * Get the path to the cron status JSON file.
     */
    private function getStatusFilePath(): ?string
    {
        $dbPath = (string) $this->config->get('db_path', '');
        $dataDir = $dbPath !== '' ? dirname($dbPath) : dirname(__DIR__, 2) . '/data';

        if (!is_dir($dataDir)) {
            return null;
        }

        return $dataDir . '/cron_status.json';
    }
}
