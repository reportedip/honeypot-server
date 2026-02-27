<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Admin;

use ReportedIp\Honeypot\Detection\CategoryRegistry;
use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Persistence\Logger;

/**
 * Log viewer for the admin panel.
 *
 * Provides paginated, filterable access to honeypot log entries
 * with export capabilities.
 */
final class LogViewer
{
    private Database $db;
    private Logger $logger;

    private const PER_PAGE = 50;

    public function __construct(Database $db, Logger $logger)
    {
        $this->db = $db;
        $this->logger = $logger;
    }

    /**
     * Get paginated log entries with optional filters.
     *
     * @param array<string, mixed> $filters Supported keys: ip, category, method, sent, search
     * @return array{logs: array, total: int, page: int, pages: int, per_page: int}
     */
    public function getPage(int $page = 1, array $filters = []): array
    {
        $page = max(1, $page);
        $offset = ($page - 1) * self::PER_PAGE;

        $where = [];
        $params = [];

        if (!empty($filters['ip'])) {
            $where[] = 'ip = ?';
            $params[] = $filters['ip'];
        }

        if (!empty($filters['category'])) {
            $where[] = 'categories LIKE ?';
            $params[] = '%' . $filters['category'] . '%';
        }

        if (!empty($filters['method'])) {
            $where[] = 'request_method = ?';
            $params[] = strtoupper($filters['method']);
        }

        if (isset($filters['sent']) && $filters['sent'] !== '') {
            $where[] = 'sent = ?';
            $params[] = (int) $filters['sent'];
        }

        if (!empty($filters['search'])) {
            $where[] = '(ip LIKE ? OR request_uri LIKE ? OR comment LIKE ? OR user_agent LIKE ?)';
            $searchTerm = '%' . $filters['search'] . '%';
            $params[] = $searchTerm;
            $params[] = $searchTerm;
            $params[] = $searchTerm;
            $params[] = $searchTerm;
        }

        $whereClause = '';
        if (!empty($where)) {
            $whereClause = 'WHERE ' . implode(' AND ', $where);
        }

        // Get total count
        $countSql = sprintf('SELECT COUNT(*) FROM honeypot_logs %s', $whereClause);
        $total = (int) $this->db->query($countSql, $params)->fetchColumn();
        $pages = max(1, (int) ceil($total / self::PER_PAGE));

        // Get page data
        $dataSql = sprintf(
            'SELECT * FROM honeypot_logs %s ORDER BY timestamp DESC LIMIT %d OFFSET %d',
            $whereClause,
            self::PER_PAGE,
            $offset
        );
        $logs = $this->db->query($dataSql, $params)->fetchAll();

        return [
            'logs'     => $logs,
            'total'    => $total,
            'page'     => $page,
            'pages'    => $pages,
            'per_page' => self::PER_PAGE,
        ];
    }

    /**
     * Get a single log entry by ID.
     *
     * @return array<string, mixed>|null
     */
    public function getEntry(int $id): ?array
    {
        $result = $this->db->query(
            'SELECT * FROM honeypot_logs WHERE id = ?',
            [$id]
        )->fetch();

        return $result !== false ? $result : null;
    }

    /**
     * Get distinct category IDs used in logs, with names from CategoryRegistry.
     *
     * @return array<int, array{id: string, name: string}>
     */
    public function getUsedCategories(): array
    {
        $stmt = $this->db->query(
            'SELECT DISTINCT categories FROM honeypot_logs ORDER BY categories'
        );

        $seen = [];
        foreach ($stmt->fetchAll() as $row) {
            $cats = explode(',', $row['categories']);
            foreach ($cats as $cat) {
                $cat = trim($cat);
                if ($cat !== '' && is_numeric($cat) && !isset($seen[$cat])) {
                    $seen[$cat] = true;
                }
            }
        }

        $categories = [];
        foreach (array_keys($seen) as $catId) {
            $categories[] = [
                'id'   => $catId,
                'name' => CategoryRegistry::getName((int) $catId),
            ];
        }

        usort($categories, fn(array $a, array $b) => (int) $a['id'] <=> (int) $b['id']);
        return $categories;
    }

    /**
     * Get distinct HTTP methods used in logs.
     *
     * @return string[]
     */
    public function getUsedMethods(): array
    {
        $stmt = $this->db->query(
            'SELECT DISTINCT request_method FROM honeypot_logs WHERE request_method IS NOT NULL ORDER BY request_method'
        );

        return array_column($stmt->fetchAll(), 'request_method');
    }
}
