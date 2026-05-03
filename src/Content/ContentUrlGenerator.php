<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Content;

/**
 * Generates CMS-specific URLs for content entries.
 */
final class ContentUrlGenerator
{
    /**
     * Get the URL for a content entry based on CMS profile.
     *
     * @param array<string, mixed> $content
     */
    public static function getPostUrl(array $content): string
    {
        $profile = $content['cms_profile'] ?? 'wordpress';
        $slug = $content['slug'] ?? '';
        $type = $content['content_type'] ?? 'post';

        if ($profile === 'wordpress') {
            // Pages use a top-level permalink (/sample-page/),
            // posts use the date-based archive URL (/YYYY/MM/slug/).
            if ($type === 'page') {
                return '/' . $slug . '/';
            }
            return '/' . date('Y/m', strtotime($content['published_date'] ?? 'now')) . '/' . $slug . '/';
        }

        return match ($profile) {
            'drupal' => '/node/' . ($content['id'] ?? 0),
            'joomla' => '/blog/' . $slug,
            default  => '/' . $slug,
        };
    }

    /**
     * Extract a slug from a URL path for a given CMS profile.
     */
    public static function extractSlug(string $path, string $cmsProfile): ?string
    {
        if ($cmsProfile === 'wordpress') {
            // Date-based post permalink: /YYYY/MM/slug/
            if (preg_match('#^/\d{4}/\d{2}/([\w-]+)/?$#', $path, $m)) {
                return $m[1];
            }
            // Top-level page permalink: /slug/
            if (preg_match('#^/([a-z0-9][\w-]*)/?$#i', $path, $m)) {
                return $m[1];
            }
            return null;
        }

        return match ($cmsProfile) {
            'drupal', 'joomla' => preg_match('#^/blog/([\w-]+)/?$#', $path, $m) ? $m[1] : null,
            default => null,
        };
    }

    /**
     * Extract an ID from a URL path for a given CMS profile.
     */
    public static function extractId(string $path, string $cmsProfile): ?int
    {
        if ($cmsProfile === 'drupal') {
            if (preg_match('#^/node/(\d+)$#', $path, $m)) {
                return (int) $m[1];
            }
        }
        return null;
    }

    /**
     * Extract a content ID from query parameters.
     *
     * WordPress query-style permalinks: /?p=N (post) or /?page_id=N (page).
     *
     * @param array<string, mixed> $queryParams
     */
    public static function extractIdFromQuery(array $queryParams, string $cmsProfile): ?int
    {
        if ($cmsProfile === 'wordpress') {
            if (isset($queryParams['p']) && is_numeric($queryParams['p'])) {
                return (int) $queryParams['p'];
            }
            if (isset($queryParams['page_id']) && is_numeric($queryParams['page_id'])) {
                return (int) $queryParams['page_id'];
            }
        }
        return null;
    }
}
