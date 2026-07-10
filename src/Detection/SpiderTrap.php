<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection;

/**
 * Honeytoken paths for the spider trap.
 *
 * These paths are advertised only where an automated client would find them:
 * as Disallow entries in robots.txt, as a low-priority entry in the sitemap,
 * and as a hidden (display:none) link on the home page. No human browsing the
 * site and no well-behaved search engine will ever request them, so any hit is
 * a bot that harvests robots.txt / scrapes every link — reported with
 * near-zero false positives.
 */
final class SpiderTrap
{
    /**
     * Bait paths, keyed by how they are advertised. Values are absolute paths.
     *
     * @var array<string, string>
     */
    private const PATHS = [
        'robots'  => '/wp-admin-backup-9f3a2c/',
        'sitemap' => '/internal/private-report-x7k2d/',
        'hidden'  => '/secure-vault-q4m8/',
    ];

    /**
     * The path advertised as a Disallow entry in robots.txt.
     */
    public static function robotsPath(): string
    {
        return self::PATHS['robots'];
    }

    /**
     * The path seeded into the XML sitemap.
     */
    public static function sitemapPath(): string
    {
        return self::PATHS['sitemap'];
    }

    /**
     * The path embedded as a hidden link on the home page.
     */
    public static function hiddenPath(): string
    {
        return self::PATHS['hidden'];
    }

    /**
     * All bait paths.
     *
     * @return string[]
     */
    public static function all(): array
    {
        return array_values(self::PATHS);
    }

    /**
     * Whether the given request path is one of the bait paths.
     */
    public static function matches(string $path): bool
    {
        $normalized = rtrim($path, '/') . '/';
        foreach (self::PATHS as $bait) {
            if ($normalized === $bait || $path === rtrim($bait, '/')) {
                return true;
            }
        }
        return false;
    }
}
