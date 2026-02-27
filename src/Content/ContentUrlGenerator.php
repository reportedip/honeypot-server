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

        return match ($profile) {
            'wordpress' => '/' . date('Y/m', strtotime($content['published_date'] ?? 'now')) . '/' . ($content['slug'] ?? '') . '/',
            'drupal'    => '/node/' . ($content['id'] ?? 0),
            'joomla'    => '/blog/' . ($content['slug'] ?? ''),
            default     => '/' . ($content['slug'] ?? ''),
        };
    }

    /**
     * Extract a slug from a URL path for a given CMS profile.
     */
    public static function extractSlug(string $path, string $cmsProfile): ?string
    {
        return match ($cmsProfile) {
            'wordpress' => preg_match('#^/\d{4}/\d{2}/([\w-]+)/?$#', $path, $m) ? $m[1] : null,
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
}
