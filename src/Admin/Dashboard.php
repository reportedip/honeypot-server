<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Admin;

use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Detection\CategoryRegistry;
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

        $chartRanges = [
            '24h' => $this->getChartData('24h'),
            '7d'  => $this->getChartData('7d'),
            '30d' => $this->getChartData('30d'),
        ];

        return [
            'stats'              => $stats,
            'recent_logs'        => $this->logger->getRecentLogs(12),
            'whitelist'          => $this->whitelist->getAll(),
            'system'             => $this->getSystemInfo(),
            'chart_data'         => $chartRanges['24h'],
            'chart_data_ranges'  => $chartRanges,
            'cron_status'        => $this->getCronStatus(),
            'recent_failures'    => $this->getRecentFailures(5),
            'visitor_stats'      => $this->getVisitorStats(),
            'trends'             => $this->getTrends(),
            'severity_breakdown' => $this->getSeverityBreakdown(7),
            'top_uris'           => $this->getTopUris(8, 7),
            'intel'              => $this->getIntelData(),
            'webhook_summary'    => $this->getWebhookSummary(),
        ];
    }

    /**
     * Get short-term trend indicators: today vs. yesterday and first-seen IPs.
     *
     * @return array{today: int, yesterday: int, change_pct: ?int, new_ips_today: int}
     */
    public function getTrends(): array
    {
        try {
            $today = (int) $this->db->query(
                "SELECT COUNT(*) FROM honeypot_logs WHERE DATE(timestamp) = DATE('now')"
            )->fetchColumn();

            $yesterday = (int) $this->db->query(
                "SELECT COUNT(*) FROM honeypot_logs WHERE DATE(timestamp) = DATE('now', '-1 day')"
            )->fetchColumn();

            $newIpsToday = (int) $this->db->query(
                "SELECT COUNT(*) FROM (
                    SELECT ip FROM honeypot_logs GROUP BY ip HAVING DATE(MIN(timestamp)) = DATE('now')
                )"
            )->fetchColumn();

            $changePct = null;
            if ($yesterday > 0) {
                $changePct = (int) round((($today - $yesterday) / $yesterday) * 100);
            }

            return [
                'today'         => $today,
                'yesterday'     => $yesterday,
                'change_pct'    => $changePct,
                'new_ips_today' => $newIpsToday,
            ];
        } catch (\Throwable $e) {
            return ['today' => 0, 'yesterday' => 0, 'change_pct' => null, 'new_ips_today' => 0];
        }
    }

    /**
     * Bucket recent events by severity class (via each event's highest category severity).
     *
     * @return array{buckets: array{critical: int, high: int, medium: int, low: int}, total: int, days: int}
     */
    public function getSeverityBreakdown(int $days = 7): array
    {
        $buckets = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
        $total = 0;

        try {
            $rows = $this->db->query(
                "SELECT categories, COUNT(*) as cnt FROM honeypot_logs
                 WHERE timestamp >= datetime('now', '-' || ? || ' days')
                 GROUP BY categories",
                [$days]
            )->fetchAll();

            foreach ($rows as $row) {
                $maxSeverity = 0;
                foreach (explode(',', (string) $row['categories']) as $cat) {
                    $cat = trim($cat);
                    if ($cat !== '' && is_numeric($cat)) {
                        $maxSeverity = max($maxSeverity, CategoryRegistry::getSeverity((int) $cat));
                    }
                }

                if ($maxSeverity >= 8) {
                    $class = 'critical';
                } elseif ($maxSeverity >= 5) {
                    $class = 'high';
                } elseif ($maxSeverity >= 3) {
                    $class = 'medium';
                } else {
                    $class = 'low';
                }

                $buckets[$class] += (int) $row['cnt'];
                $total += (int) $row['cnt'];
            }
        } catch (\Throwable $e) {
            // Keep zeroed buckets on failure
        }

        return ['buckets' => $buckets, 'total' => $total, 'days' => $days];
    }

    /**
     * Get the most-targeted request paths (query strings stripped).
     *
     * @return array<int, array{path: string, cnt: int}>
     */
    public function getTopUris(int $limit = 8, int $days = 7): array
    {
        try {
            return $this->db->query(
                "SELECT CASE WHEN instr(request_uri, '?') > 0
                             THEN substr(request_uri, 1, instr(request_uri, '?') - 1)
                             ELSE request_uri END AS path,
                        COUNT(*) as cnt
                 FROM honeypot_logs
                 WHERE timestamp >= datetime('now', '-' || ? || ' days')
                 GROUP BY path ORDER BY cnt DESC LIMIT ?",
                [$days, $limit]
            )->fetchAll();
        } catch (\Throwable $e) {
            return [];
        }
    }

    /**
     * Get threat-intel summary and recent activity for the dashboard.
     *
     * @return array{summary: array<string, int>, recent_triggered: array<int, array<string, mixed>>, recent_captures: array<int, array<string, mixed>>}
     */
    public function getIntelData(): array
    {
        $intel = new ThreatIntel($this->db);

        return [
            'summary'          => $intel->getSummary(),
            'recent_triggered' => $intel->getRecentTriggered(5),
            'recent_captures'  => $intel->getRecentCaptures(5),
        ];
    }

    /**
     * Get webhook delivery health summary.
     *
     * @return array{total: int, enabled: int, failing: int}
     */
    public function getWebhookSummary(): array
    {
        try {
            $row = $this->db->query(
                'SELECT COUNT(*) AS total,
                        COALESCE(SUM(CASE WHEN enabled = 1 THEN 1 ELSE 0 END), 0) AS enabled,
                        COALESCE(SUM(CASE WHEN enabled = 1 AND failure_count > 0 THEN 1 ELSE 0 END), 0) AS failing
                 FROM honeypot_webhooks'
            )->fetch();

            return [
                'total'   => (int) ($row['total'] ?? 0),
                'enabled' => (int) ($row['enabled'] ?? 0),
                'failing' => (int) ($row['failing'] ?? 0),
            ];
        } catch (\Throwable $e) {
            return ['total' => 0, 'enabled' => 0, 'failing' => 0];
        }
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
     * Get data for the activity chart, bucketed by hour (24h) or by day (7d / 30d).
     *
     * @param string $range '24h', '7d', or '30d'
     * @return array<int, array{label: string, count: int}>
     */
    public function getChartData(string $range = '24h'): array
    {
        if ($range === '7d') {
            return $this->getDailyChartData(7);
        }
        if ($range === '30d') {
            return $this->getDailyChartData(30);
        }
        return $this->getHourlyChartData(24);
    }

    /**
     * Hourly buckets over the last $hours hours.
     *
     * @return array<int, array{label: string, count: int}>
     */
    private function getHourlyChartData(int $hours): array
    {
        $stmt = $this->db->query(
            "SELECT strftime('%Y-%m-%d %H:00', timestamp) as bucket, COUNT(*) as count
             FROM honeypot_logs
             WHERE timestamp >= datetime('now', '-' || ? || ' hours')
             GROUP BY bucket
             ORDER BY bucket ASC",
            [$hours]
        );

        $rows = $stmt->fetchAll();
        $byBucket = [];
        foreach ($rows as $row) {
            $byBucket[$row['bucket']] = (int) $row['count'];
        }

        $chart = [];
        $start = (new \DateTime())->modify('-' . ($hours - 1) . ' hours');

        for ($i = 0; $i < $hours; $i++) {
            $key = $start->format('Y-m-d H:00');
            $chart[] = [
                'label' => $start->format('H:00'),
                'count' => $byBucket[$key] ?? 0,
            ];
            $start->modify('+1 hour');
        }

        return $chart;
    }

    /**
     * Daily buckets over the last $days days.
     *
     * @return array<int, array{label: string, count: int}>
     */
    private function getDailyChartData(int $days): array
    {
        $stmt = $this->db->query(
            "SELECT strftime('%Y-%m-%d', timestamp) as bucket, COUNT(*) as count
             FROM honeypot_logs
             WHERE timestamp >= date('now', '-' || ? || ' days')
             GROUP BY bucket
             ORDER BY bucket ASC",
            [$days - 1]
        );

        $rows = $stmt->fetchAll();
        $byBucket = [];
        foreach ($rows as $row) {
            $byBucket[$row['bucket']] = (int) $row['count'];
        }

        $chart = [];
        $start = (new \DateTime())->setTime(0, 0, 0)->modify('-' . ($days - 1) . ' days');

        for ($i = 0; $i < $days; $i++) {
            $key = $start->format('Y-m-d');
            $chart[] = [
                'label' => $start->format('m-d'),
                'count' => $byBucket[$key] ?? 0,
            ];
            $start->modify('+1 day');
        }

        return $chart;
    }

    /**
     * Get the most recent failed report attempts for the dashboard.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getRecentFailures(int $limit = 5): array
    {
        $stmt = $this->db->query(
            'SELECT id, ip, request_uri, request_method, categories,
                    last_failure_at, last_failure_reason, failed_attempts, sent
               FROM honeypot_logs
              WHERE last_failure_at IS NOT NULL
              ORDER BY last_failure_at DESC
              LIMIT ?',
            [$limit]
        );

        return $stmt->fetchAll();
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
