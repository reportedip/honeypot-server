<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Content;

use ReportedIp\Honeypot\Persistence\Database;

/**
 * CRUD repository for the honeypot_content table.
 */
final class ContentRepository
{
    private Database $db;

    public function __construct(Database $db)
    {
        $this->db = $db;
    }

    /**
     * Get published content for a CMS profile.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getPublished(string $profile, int $limit = 10): array
    {
        $stmt = $this->db->query(
            'SELECT * FROM honeypot_content
             WHERE cms_profile = ? AND status = ?
             ORDER BY published_date DESC
             LIMIT ?',
            [$profile, 'published', $limit]
        );
        return $stmt->fetchAll();
    }

    /**
     * Get a content entry by slug and profile.
     *
     * @return array<string, mixed>|null
     */
    public function getBySlug(string $profile, string $slug): ?array
    {
        $stmt = $this->db->query(
            'SELECT * FROM honeypot_content WHERE cms_profile = ? AND slug = ? AND status = ? LIMIT 1',
            [$profile, $slug, 'published']
        );
        $row = $stmt->fetch();
        return $row !== false ? $row : null;
    }

    /**
     * Get a content entry by ID.
     *
     * @return array<string, mixed>|null
     */
    public function getById(int $id): ?array
    {
        $stmt = $this->db->query(
            'SELECT * FROM honeypot_content WHERE id = ? LIMIT 1',
            [$id]
        );
        $row = $stmt->fetch();
        return $row !== false ? $row : null;
    }

    /**
     * Get entries for sitemap generation (minimal data).
     *
     * @return array<int, array<string, mixed>>
     */
    public function getForSitemap(string $profile): array
    {
        $stmt = $this->db->query(
            'SELECT id, slug, published_date FROM honeypot_content
             WHERE cms_profile = ? AND status = ?
             ORDER BY published_date DESC',
            [$profile, 'published']
        );
        return $stmt->fetchAll();
    }

    /**
     * Insert a new content entry and return the ID.
     *
     * @param array<string, mixed> $data
     */
    public function insert(array $data): int
    {
        return $this->db->insert('honeypot_content', $data);
    }

    /**
     * Update a content entry by ID.
     *
     * @param array<string, mixed> $data
     */
    /** @var string[] Allowed column names for update operations. */
    private const ALLOWED_COLUMNS = [
        'cms_profile', 'title', 'slug', 'content', 'excerpt', 'author',
        'category', 'status', 'content_type', 'published_date',
        'meta_description', 'updated_at',
    ];

    public function update(int $id, array $data): bool
    {
        $data['updated_at'] = date('Y-m-d H:i:s');
        $sets = [];
        $params = [];
        foreach ($data as $column => $value) {
            if (!in_array($column, self::ALLOWED_COLUMNS, true)) {
                continue;
            }
            $sets[] = $column . ' = ?';
            $params[] = $value;
        }

        if ($sets === []) {
            return false;
        }

        $params[] = $id;

        $stmt = $this->db->query(
            'UPDATE honeypot_content SET ' . implode(', ', $sets) . ' WHERE id = ?',
            $params
        );
        return $stmt->rowCount() > 0;
    }

    /**
     * Delete a content entry by ID.
     */
    public function delete(int $id): bool
    {
        $stmt = $this->db->query('DELETE FROM honeypot_content WHERE id = ?', [$id]);
        return $stmt->rowCount() > 0;
    }

    /**
     * Count content entries for a profile.
     */
    public function countByProfile(string $profile): int
    {
        $stmt = $this->db->query(
            'SELECT COUNT(*) as cnt FROM honeypot_content WHERE cms_profile = ?',
            [$profile]
        );
        $row = $stmt->fetch();
        return (int) ($row['cnt'] ?? 0);
    }

    /**
     * Get paginated content entries.
     *
     * @return array{entries: array<int, array<string, mixed>>, total: int, page: int, per_page: int, total_pages: int}
     */
    public function getPaginated(string $profile, int $page, int $perPage = 20): array
    {
        $total = $this->countByProfile($profile);
        $totalPages = (int) ceil($total / $perPage);
        $page = max(1, min($page, max(1, $totalPages)));
        $offset = ($page - 1) * $perPage;

        $stmt = $this->db->query(
            'SELECT * FROM honeypot_content
             WHERE cms_profile = ?
             ORDER BY published_date DESC
             LIMIT ? OFFSET ?',
            [$profile, $perPage, $offset]
        );

        return [
            'entries'     => $stmt->fetchAll(),
            'total'       => $total,
            'page'        => $page,
            'per_page'    => $perPage,
            'total_pages' => $totalPages,
        ];
    }
}
