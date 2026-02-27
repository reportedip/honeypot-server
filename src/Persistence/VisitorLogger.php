<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Persistence;

use ReportedIp\Honeypot\Core\Request;

/**
 * Logs and queries visitor data from honeypot_visitors.
 */
final class VisitorLogger
{
    private Database $db;

    public function __construct(Database $db)
    {
        $this->db = $db;
    }

    /**
     * Log a visitor with rate limiting (max 1 entry per IP+UA+route per minute).
     */
    public function log(Request $request, string $type, string $botName, string $routeType): void
    {
        $ip = $request->getIp();
        $ua = $request->getUserAgent();
        $uri = $request->getUri();
        $method = $request->getMethod();

        // Rate-limit: skip if same IP+route logged within last 60s
        $stmt = $this->db->query(
            "SELECT COUNT(*) as cnt FROM honeypot_visitors
             WHERE ip = ? AND route_type = ? AND timestamp >= datetime('now', '-1 minute')",
            [$ip, $routeType]
        );
        $row = $stmt->fetch();
        if (((int) ($row['cnt'] ?? 0)) > 0) {
            return;
        }

        $this->db->insert('honeypot_visitors', [
            'ip'             => $ip,
            'user_agent'     => mb_substr($ua, 0, 500),
            'visitor_type'   => $type,
            'bot_name'       => $botName,
            'request_uri'    => mb_substr($uri, 0, 1000),
            'request_method' => $method,
            'route_type'     => $routeType,
        ]);
    }

    /**
     * Get visitor counts by type for a time period.
     *
     * @return array<string, int>
     */
    public function getStats(int $hours = 24): array
    {
        $stmt = $this->db->query(
            "SELECT visitor_type, COUNT(*) as cnt FROM honeypot_visitors
             WHERE timestamp >= datetime('now', '-' || ? || ' hours')
             GROUP BY visitor_type",
            [$hours]
        );

        $result = [
            'good_bot' => 0,
            'ai_agent' => 0,
            'bad_bot'  => 0,
            'hacker'   => 0,
            'human'    => 0,
        ];

        foreach ($stmt->fetchAll() as $row) {
            $result[$row['visitor_type']] = (int) $row['cnt'];
        }

        return $result;
    }

    /**
     * Get top bots by request count.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getTopBots(int $hours = 24, int $limit = 20): array
    {
        $stmt = $this->db->query(
            "SELECT bot_name, visitor_type, COUNT(*) as cnt FROM honeypot_visitors
             WHERE timestamp >= datetime('now', '-' || ? || ' hours')
               AND bot_name != ''
             GROUP BY bot_name, visitor_type
             ORDER BY cnt DESC
             LIMIT ?",
            [$hours, $limit]
        );
        return $stmt->fetchAll();
    }

    /**
     * Get recent visitors.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getRecentVisitors(int $limit = 50): array
    {
        $stmt = $this->db->query(
            'SELECT * FROM honeypot_visitors ORDER BY timestamp DESC LIMIT ?',
            [$limit]
        );
        return $stmt->fetchAll();
    }

    /**
     * Get hourly breakdown per visitor type for chart display.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getChartData(int $hours = 24): array
    {
        $stmt = $this->db->query(
            "SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour, visitor_type, COUNT(*) as cnt
             FROM honeypot_visitors
             WHERE timestamp >= datetime('now', '-' || ? || ' hours')
             GROUP BY hour, visitor_type
             ORDER BY hour ASC",
            [$hours]
        );

        $raw = $stmt->fetchAll();
        $byHour = [];
        foreach ($raw as $row) {
            $byHour[$row['hour']][$row['visitor_type']] = (int) $row['cnt'];
        }

        $chart = [];
        $now = new \DateTime();
        $start = (clone $now)->modify('-' . ($hours - 1) . ' hours');

        for ($i = 0; $i < $hours; $i++) {
            $hourStr = $start->format('Y-m-d H:00');
            $data = $byHour[$hourStr] ?? [];
            $chart[] = [
                'hour'     => $start->format('H:00'),
                'good_bot' => $data['good_bot'] ?? 0,
                'ai_agent' => $data['ai_agent'] ?? 0,
                'bad_bot'  => $data['bad_bot'] ?? 0,
                'hacker'   => $data['hacker'] ?? 0,
                'human'    => $data['human'] ?? 0,
            ];
            $start->modify('+1 hour');
        }

        return $chart;
    }

    /**
     * Get paginated visitors with optional filters.
     *
     * @param array<string, string> $filters
     * @return array{entries: array<int, array<string, mixed>>, total: int, page: int, per_page: int, total_pages: int}
     */
    public function getPaginated(int $page, int $perPage = 50, array $filters = []): array
    {
        $where = [];
        $params = [];

        if (!empty($filters['type'])) {
            $where[] = 'visitor_type = ?';
            $params[] = $filters['type'];
        }
        if (!empty($filters['bot_name'])) {
            $where[] = 'bot_name LIKE ?';
            $params[] = '%' . $filters['bot_name'] . '%';
        }
        if (!empty($filters['ip'])) {
            $where[] = 'ip = ?';
            $params[] = $filters['ip'];
        }

        $whereClause = !empty($where) ? 'WHERE ' . implode(' AND ', $where) : '';

        $countStmt = $this->db->query(
            'SELECT COUNT(*) as cnt FROM honeypot_visitors ' . $whereClause,
            $params
        );
        $total = (int) ($countStmt->fetch()['cnt'] ?? 0);
        $totalPages = (int) ceil($total / $perPage);
        $page = max(1, min($page, max(1, $totalPages)));
        $offset = ($page - 1) * $perPage;

        $queryParams = array_merge($params, [$perPage, $offset]);
        $stmt = $this->db->query(
            'SELECT * FROM honeypot_visitors ' . $whereClause . ' ORDER BY timestamp DESC LIMIT ? OFFSET ?',
            $queryParams
        );

        return [
            'entries'     => $stmt->fetchAll(),
            'total'       => $total,
            'page'        => $page,
            'per_page'    => $perPage,
            'total_pages' => $totalPages,
        ];
    }

    /**
     * Clean up old visitor entries.
     */
    public function cleanup(int $days): int
    {
        $stmt = $this->db->query(
            "DELETE FROM honeypot_visitors WHERE timestamp < datetime('now', '-' || ? || ' days')",
            [$days]
        );
        return $stmt->rowCount();
    }
}
