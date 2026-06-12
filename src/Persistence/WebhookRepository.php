<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Persistence;

/**
 * Repository for outbound webhook endpoints (external report targets).
 *
 * Webhooks let honeypot operators forward detections to their own
 * logging/SIEM systems, filtered by category IDs and/or analyzer names.
 */
final class WebhookRepository
{
    public function __construct(private readonly Database $db)
    {
    }

    /**
     * Add a new webhook. Returns the new ID.
     *
     * @param array<string, mixed> $data Keys: name, url, secret, categories, analyzers, enabled
     */
    public function add(array $data): int
    {
        return $this->db->insert('honeypot_webhooks', [
            'name'          => (string) ($data['name'] ?? ''),
            'url'           => (string) ($data['url'] ?? ''),
            'secret'        => (string) ($data['secret'] ?? ''),
            'categories'    => (string) ($data['categories'] ?? ''),
            'analyzers'     => (string) ($data['analyzers'] ?? ''),
            'enabled'       => (int) ($data['enabled'] ?? 1),
            'method'        => (string) ($data['method'] ?? 'POST'),
            'headers'       => (string) ($data['headers'] ?? ''),
            'body_format'   => (string) ($data['body_format'] ?? 'json'),
            'body_template' => (string) ($data['body_template'] ?? ''),
        ]);
    }

    /**
     * Update an existing webhook.
     *
     * @param array<string, mixed> $data Keys: name, url, secret, categories, analyzers
     */
    public function update(int $id, array $data): void
    {
        $this->db->query(
            'UPDATE honeypot_webhooks
                SET name = ?, url = ?, secret = ?, categories = ?, analyzers = ?,
                    method = ?, headers = ?, body_format = ?, body_template = ?
              WHERE id = ?',
            [
                (string) ($data['name'] ?? ''),
                (string) ($data['url'] ?? ''),
                (string) ($data['secret'] ?? ''),
                (string) ($data['categories'] ?? ''),
                (string) ($data['analyzers'] ?? ''),
                (string) ($data['method'] ?? 'POST'),
                (string) ($data['headers'] ?? ''),
                (string) ($data['body_format'] ?? 'json'),
                (string) ($data['body_template'] ?? ''),
                $id,
            ]
        );
    }

    public function delete(int $id): void
    {
        $this->db->query('DELETE FROM honeypot_webhooks WHERE id = ?', [$id]);
    }

    /**
     * @return array<string, mixed>|null
     */
    public function getById(int $id): ?array
    {
        $row = $this->db->query('SELECT * FROM honeypot_webhooks WHERE id = ?', [$id])->fetch();
        return $row === false ? null : $row;
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function getAll(): array
    {
        return $this->db->query('SELECT * FROM honeypot_webhooks ORDER BY id ASC')->fetchAll();
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    public function getEnabled(): array
    {
        return $this->db->query('SELECT * FROM honeypot_webhooks WHERE enabled = 1 ORDER BY id ASC')->fetchAll();
    }

    public function setEnabled(int $id, bool $enabled): void
    {
        $this->db->query('UPDATE honeypot_webhooks SET enabled = ? WHERE id = ?', [$enabled ? 1 : 0, $id]);
    }

    /**
     * Record the outcome of a delivery attempt. Success resets the failure counter.
     */
    public function recordResult(int $id, bool $success, string $status): void
    {
        if ($success) {
            $this->db->query(
                "UPDATE honeypot_webhooks
                    SET last_triggered_at = datetime('now'), last_status = ?, failure_count = 0
                  WHERE id = ?",
                [mb_substr($status, 0, 200), $id]
            );
            return;
        }

        $this->db->query(
            "UPDATE honeypot_webhooks
                SET last_triggered_at = datetime('now'), last_status = ?,
                    failure_count = COALESCE(failure_count, 0) + 1
              WHERE id = ?",
            [mb_substr($status, 0, 200), $id]
        );
    }
}
