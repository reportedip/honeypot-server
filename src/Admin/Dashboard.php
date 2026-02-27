<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Admin;

use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Persistence\Logger;
use ReportedIp\Honeypot\Persistence\VisitorLogger;
use ReportedIp\Honeypot\Persistence\Whitelist;

/**
 * Admin dashboard data provider.
 *
 * Aggregates statistics and system health information for the admin panel.
 */
final class Dashboard
{
    private Database $db;
    private Logger $logger;
    private Whitelist $whitelist;
    private Config $config;

    public function __construct(Database $db, Logger $logger, Whitelist $whitelist, Config $config)
    {
        $this->db = $db;
        $this->logger = $logger;
        $this->whitelist = $whitelist;
        $this->config = $config;
    }

    /**
     * Get all data needed for the dashboard view.
     *
     * @return array<string, mixed>
     */
    public function getData(): array
    {
        $stats = $this->logger->getStats();

        return [
            'stats'          => $stats,
            'recent_logs'    => $this->logger->getRecentLogs(15),
            'whitelist'      => $this->whitelist->getAll(),
            'system'         => $this->getSystemInfo(),
            'chart_data'     => $this->getChartData(),
            'cron_status'    => $this->getCronStatus(),
            'visitor_stats'  => $this->getVisitorStats(),
        ];
    }

    /**
     * Get system health and configuration info.
     *
     * @return array<string, mixed>
     */
    public function getSystemInfo(): array
    {
        $dbPath = $this->config->get('db_path', '');
        $dbSize = file_exists($dbPath) ? filesize($dbPath) : 0;

        return [
            'php_version'   => PHP_VERSION,
            'cms_profile'   => $this->config->get('cms_profile', 'unknown'),
            'api_configured' => !empty($this->config->get('api_key', '')),
            'db_size'       => $this->formatBytes($dbSize !== false ? $dbSize : 0),
            'db_size_raw'   => $dbSize !== false ? $dbSize : 0,
            'cache_path'    => $this->config->get('cache_path', ''),
            'queue_mode'    => (string) $this->config->get('queue_mode', 'web'),
            'debug_mode'    => (bool) $this->config->get('debug', false),
            'retention_days' => (int) $this->config->get('log_retention_days', 90),
            'server_time'   => date('Y-m-d H:i:s'),
            'app_version'   => trim(@file_get_contents(dirname(__DIR__, 2) . '/VERSION') ?: 'unknown'),
        ];
    }

    /**
     * Get data for the activity chart (events per hour, last 24 hours).
     *
     * @return array<int, array{hour: string, count: int}>
     */
    public function getChartData(): array
    {
        $stmt = $this->db->query(
            "SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour, COUNT(*) as count
             FROM honeypot_logs
             WHERE timestamp >= datetime('now', '-24 hours')
             GROUP BY hour
             ORDER BY hour ASC"
        );

        $rows = $stmt->fetchAll();

        // Fill gaps with zero counts
        $chart = [];
        $now = new \DateTime();
        $start = (clone $now)->modify('-23 hours');

        for ($i = 0; $i < 24; $i++) {
            $hourStr = $start->format('Y-m-d H:00');
            $count = 0;

            foreach ($rows as $row) {
                if ($row['hour'] === $hourStr) {
                    $count = (int) $row['count'];
                    break;
                }
            }

            $chart[] = [
                'hour'  => $start->format('H:00'),
                'count' => $count,
            ];

            $start->modify('+1 hour');
        }

        return $chart;
    }

    /**
     * Get top attacking IPs with event counts.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getTopAttackers(int $limit = 20): array
    {
        $stmt = $this->db->query(
            'SELECT ip, COUNT(*) as total,
                    MAX(timestamp) as last_seen,
                    GROUP_CONCAT(DISTINCT categories) as all_categories
             FROM honeypot_logs
             GROUP BY ip
             ORDER BY total DESC
             LIMIT ?',
            [$limit]
        );

        return $stmt->fetchAll();
    }

    /**
     * Get cron job status from the status file written by cli.php process-queue.
     *
     * @return array<string, mixed>
     */
    public function getCronStatus(): array
    {
        $dbPath = $this->config->get('db_path', '');
        $dataDir = $dbPath !== '' ? dirname($dbPath) : '';
        $statusFile = $dataDir !== '' ? $dataDir . '/cron_status.json' : '';

        $status = [
            'configured'  => false,
            'last_run'    => null,
            'last_result' => null,
            'history'     => [],
            'total_sent'  => 0,
            'total_failed' => 0,
            'runs_count'  => 0,
            'health'      => 'unknown',
            'age_minutes' => null,
        ];

        if ($statusFile === '' || !file_exists($statusFile)) {
            $queueMode = (string) $this->config->get('queue_mode', 'web');
            if ($queueMode === 'web') {
                $status['configured'] = true;
                $status['health'] = 'healthy';
            }
            return $status;
        }

        $data = @json_decode((string) file_get_contents($statusFile), true);
        if (!is_array($data)) {
            return $status;
        }

        $status['configured'] = true;
        $status['last_run'] = $data['last_run'] ?? null;
        $status['last_result'] = $data['last_result'] ?? null;
        $status['history'] = $data['history'] ?? [];
        $status['total_sent'] = $data['total_sent'] ?? 0;
        $status['total_failed'] = $data['total_failed'] ?? 0;
        $status['runs_count'] = $data['runs_count'] ?? 0;

        // Calculate age and health
        if ($status['last_run'] !== null) {
            $lastRunTs = strtotime($status['last_run']);
            if ($lastRunTs !== false) {
                $ageMinutes = (int) round((time() - $lastRunTs) / 60);
                $status['age_minutes'] = $ageMinutes;

                if ($ageMinutes <= 10) {
                    $status['health'] = 'healthy';
                } elseif ($ageMinutes <= 30) {
                    $status['health'] = 'warning';
                } else {
                    $status['health'] = 'critical';
                }
            }
        }

        // Check if last run had errors
        if (($status['last_result']['had_errors'] ?? false) && $status['health'] === 'healthy') {
            $status['health'] = 'warning';
        }

        return $status;
    }

    /**
     * Get visitor statistics for the dashboard.
     *
     * @return array<string, mixed>
     */
    public function getVisitorStats(): array
    {
        try {
            $visitorLogger = new VisitorLogger($this->db);
            return [
                'counts'   => $visitorLogger->getStats(24),
                'top_bots' => $visitorLogger->getTopBots(24, 10),
            ];
        } catch (\Throwable $e) {
            return [
                'counts'   => ['good_bot' => 0, 'ai_agent' => 0, 'bad_bot' => 0, 'hacker' => 0, 'human' => 0],
                'top_bots' => [],
            ];
        }
    }

    /**
     * Format bytes into a human-readable string.
     */
    private function formatBytes(int $bytes): string
    {
        if ($bytes === 0) {
            return '0 B';
        }

        $units = ['B', 'KB', 'MB', 'GB'];
        $factor = (int) floor(log($bytes, 1024));
        $factor = min($factor, count($units) - 1);

        return sprintf('%.1f %s', $bytes / pow(1024, $factor), $units[$factor]);
    }
}
