<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Persistence;

use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\DetectionResult;

/**
 * Honeypot event logger.
 *
 * Records detection events into the SQLite database with per-IP rate limiting
 * to prevent log flooding from single sources.
 */
final class Logger
{
    private Database $db;
    private Config $config;

    /** @var array<string, int[]> In-memory rate limit tracker: IP => [timestamps] */
    private array $rateLimitCache = [];

    public function __construct(Database $db, Config $config)
    {
        $this->db = $db;
        $this->config = $config;
    }

    /**
     * Log a request with its detection results.
     *
     * @param DetectionResult[] $detectionResults
     */
    public function log(Request $request, array $detectionResults): void
    {
        $ip = $request->getIp();

        if ($this->isRateLimited($ip)) {
            return;
        }

        // Merge categories from all results
        $allCategories = [];
        $comments = [];
        foreach ($detectionResults as $result) {
            $allCategories = array_merge($allCategories, $result->getCategories());
            $comments[] = sprintf('[%s] %s', $result->getAnalyzerName(), $result->getComment());
        }

        $allCategories = array_unique($allCategories);
        sort($allCategories);

        $postData = $request->getPostData();
        $postJson = null;
        if (!empty($postData)) {
            $encoded = json_encode($postData, JSON_UNESCAPED_SLASHES);
            $postJson = $encoded !== false ? $encoded : '{"error":"encoding failed"}';
        }

        $this->db->insert('honeypot_logs', [
            'ip'             => $ip,
            'categories'     => implode(',', $allCategories),
            'comment'        => implode(' | ', $comments),
            'user_agent'     => $request->getUserAgent(),
            'request_uri'    => $request->getUri(),
            'request_method' => $request->getMethod(),
            'post_data'      => $postJson,
        ]);

        // Track for rate limiting
        $this->trackRequest($ip);
    }

    /**
     * Get recent log entries.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getRecentLogs(int $limit = 100, int $offset = 0): array
    {
        $stmt = $this->db->query(
            'SELECT * FROM honeypot_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?',
            [$limit, $offset]
        );
        return $stmt->fetchAll();
    }

    /**
     * Get log entries for a specific IP.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getLogsByIp(string $ip, int $limit = 50): array
    {
        $stmt = $this->db->query(
            'SELECT * FROM honeypot_logs WHERE ip = ? ORDER BY timestamp DESC LIMIT ?',
            [$ip, $limit]
        );
        return $stmt->fetchAll();
    }

    /**
     * Get unsent log entries (pending API reporting).
     *
     * @return array<int, array<string, mixed>>
     */
    public function getUnsent(?int $limit = null): array
    {
        if ($limit !== null) {
            $stmt = $this->db->query(
                'SELECT * FROM honeypot_logs WHERE sent = 0 ORDER BY timestamp ASC LIMIT ?',
                [$limit]
            );
        } else {
            $stmt = $this->db->query(
                'SELECT * FROM honeypot_logs WHERE sent = 0 ORDER BY timestamp ASC'
            );
        }
        return $stmt->fetchAll();
    }

    /**
     * Mark log entries as sent to the API.
     *
     * @param int[] $ids
     */
    public function markSent(array $ids): void
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
     * Mark log entries for whitelisted IPs as sent (skip reporting).
     *
     * @param int[] $ids
     */
    public function markWhitelisted(array $ids): void
    {
        if (empty($ids)) {
            return;
        }

        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $this->db->query(
            sprintf('UPDATE honeypot_logs SET sent = 2 WHERE id IN (%s)', $placeholders),
            $ids
        );
    }

    /**
     * Get aggregate statistics.
     *
     * @return array<string, mixed>
     */
    public function getStats(): array
    {
        $pdo = $this->db->getConnection();

        $total = (int) $pdo->query('SELECT COUNT(*) FROM honeypot_logs')->fetchColumn();

        $today = (int) $this->db->query(
            'SELECT COUNT(*) FROM honeypot_logs WHERE DATE(timestamp) = DATE(\'now\')'
        )->fetchColumn();

        $uniqueIps = (int) $pdo->query('SELECT COUNT(DISTINCT ip) FROM honeypot_logs')->fetchColumn();

        $pending = (int) $pdo->query('SELECT COUNT(*) FROM honeypot_logs WHERE sent = 0')->fetchColumn();

        // Top categories
        $catStmt = $pdo->query(
            'SELECT categories, COUNT(*) as cnt FROM honeypot_logs GROUP BY categories ORDER BY cnt DESC LIMIT 10'
        );
        $topCategories = $catStmt->fetchAll();

        // Top IPs
        $ipStmt = $pdo->query(
            'SELECT ip, COUNT(*) as cnt FROM honeypot_logs GROUP BY ip ORDER BY cnt DESC LIMIT 10'
        );
        $topIps = $ipStmt->fetchAll();

        return [
            'total'          => $total,
            'today'          => $today,
            'unique_ips'     => $uniqueIps,
            'pending'        => $pending,
            'top_categories' => $topCategories,
            'top_ips'        => $topIps,
        ];
    }

    /**
     * Delete log entries older than the given number of days.
     *
     * @return int Number of deleted entries.
     */
    public function cleanup(int $days): int
    {
        $stmt = $this->db->query(
            'DELETE FROM honeypot_logs WHERE timestamp < datetime(\'now\', ?)',
            ['-' . $days . ' days']
        );
        return $stmt->rowCount();
    }

    /**
     * Check if the given IP has exceeded the per-minute rate limit.
     */
    public function isRateLimited(string $ip): bool
    {
        $limit = (int) $this->config->get('rate_limit_per_ip', 10);
        $now = time();
        $windowStart = $now - 60;

        // Check in-memory cache first
        if (isset($this->rateLimitCache[$ip])) {
            $this->rateLimitCache[$ip] = array_filter(
                $this->rateLimitCache[$ip],
                static function (int $ts) use ($windowStart): bool {
                    return $ts >= $windowStart;
                }
            );

            if (count($this->rateLimitCache[$ip]) >= $limit) {
                return true;
            }
        }

        // Also check database for cross-request persistence
        $count = (int) $this->db->query(
            'SELECT COUNT(*) FROM honeypot_logs WHERE ip = ? AND timestamp >= datetime(\'now\', \'-1 minute\')',
            [$ip]
        )->fetchColumn();

        return $count >= $limit;
    }

    /**
     * Track a request timestamp for rate limiting.
     */
    private function trackRequest(string $ip): void
    {
        if (!isset($this->rateLimitCache[$ip])) {
            $this->rateLimitCache[$ip] = [];
        }
        $this->rateLimitCache[$ip][] = time();
    }
}
