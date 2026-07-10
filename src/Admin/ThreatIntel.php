<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Admin;

use ReportedIp\Honeypot\Persistence\Database;

/**
 * Read model for the admin threat-intel page.
 *
 * Provides paginated access to issued honeytokens (canary credentials) and
 * captured payloads (fake-admin uploads, webshell POSTs, DB-admin logins).
 */
final class ThreatIntel
{
    private const PER_PAGE = 50;

    public function __construct(private readonly Database $db) {}

    /**
     * Summary counters for the page header.
     *
     * @return array{tokens_issued: int, tokens_triggered: int, captures: int, capture_bytes: int}
     */
    public function getSummary(): array
    {
        return [
            'tokens_issued'    => $this->count('SELECT COUNT(*) FROM honeypot_honeytokens'),
            'tokens_triggered' => $this->count('SELECT COUNT(*) FROM honeypot_honeytokens WHERE triggered = 1'),
            'captures'         => $this->count('SELECT COUNT(*) FROM honeypot_captures'),
            'capture_bytes'    => $this->count('SELECT COALESCE(SUM(size), 0) FROM honeypot_captures'),
        ];
    }

    /**
     * Get paginated honeytokens, triggered ones first.
     *
     * @return array{rows: array<int, array<string, mixed>>, total: int, page: int, pages: int}
     */
    public function getHoneytokens(int $page = 1): array
    {
        $page = max(1, $page);
        $offset = ($page - 1) * self::PER_PAGE;

        $total = $this->count('SELECT COUNT(*) FROM honeypot_honeytokens');
        $rows = $this->db->query(
            'SELECT * FROM honeypot_honeytokens ORDER BY triggered DESC, COALESCE(triggered_at, issued_at) DESC LIMIT ? OFFSET ?',
            [self::PER_PAGE, $offset]
        )->fetchAll();

        return [
            'rows'  => $rows,
            'total' => $total,
            'page'  => $page,
            'pages' => max(1, (int) ceil($total / self::PER_PAGE)),
        ];
    }

    /**
     * Get paginated captured payloads (newest first).
     *
     * @return array{rows: array<int, array<string, mixed>>, total: int, page: int, pages: int}
     */
    public function getCaptures(int $page = 1): array
    {
        $page = max(1, $page);
        $offset = ($page - 1) * self::PER_PAGE;

        $total = $this->count('SELECT COUNT(*) FROM honeypot_captures');
        // Omit the (potentially large) content blob from the list query.
        $rows = $this->db->query(
            'SELECT id, ip, capture_type, filename, content_type, size, request_uri, user_agent, timestamp
             FROM honeypot_captures ORDER BY timestamp DESC LIMIT ? OFFSET ?',
            [self::PER_PAGE, $offset]
        )->fetchAll();

        return [
            'rows'  => $rows,
            'total' => $total,
            'page'  => $page,
            'pages' => max(1, (int) ceil($total / self::PER_PAGE)),
        ];
    }

    /**
     * Get the most recently triggered honeytokens (for the dashboard feed).
     *
     * @return array<int, array<string, mixed>>
     */
    public function getRecentTriggered(int $limit = 5): array
    {
        try {
            return $this->db->query(
                'SELECT token, token_type, issued_to_ip, triggered_by_ip, triggered_at, trigger_count
                 FROM honeypot_honeytokens WHERE triggered = 1
                 ORDER BY triggered_at DESC LIMIT ?',
                [$limit]
            )->fetchAll();
        } catch (\Throwable $e) {
            return [];
        }
    }

    /**
     * Get the most recent captured payloads without content (for the dashboard feed).
     *
     * @return array<int, array<string, mixed>>
     */
    public function getRecentCaptures(int $limit = 5): array
    {
        try {
            return $this->db->query(
                'SELECT id, ip, capture_type, filename, size, timestamp
                 FROM honeypot_captures ORDER BY timestamp DESC LIMIT ?',
                [$limit]
            )->fetchAll();
        } catch (\Throwable $e) {
            return [];
        }
    }

    /**
     * Get a single capture row including its decoded payload.
     *
     * @return array<string, mixed>|null
     */
    public function getCapture(int $id): ?array
    {
        $row = $this->db->query('SELECT * FROM honeypot_captures WHERE id = ?', [$id])->fetch();
        if ($row === false || $row === null) {
            return null;
        }
        $row['content'] = base64_decode((string) ($row['content_b64'] ?? ''), true) ?: '';
        return $row;
    }

    private function count(string $sql): int
    {
        try {
            return (int) $this->db->getConnection()->query($sql)->fetchColumn();
        } catch (\Throwable $e) {
            return 0;
        }
    }
}
