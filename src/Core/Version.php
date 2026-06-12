<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Core;

/**
 * Central access to the current application version.
 *
 * Single source of truth is the VERSION file in the project root —
 * the same file the self-update system compares against GitHub releases.
 */
final class Version
{
    private static ?string $cached = null;

    /**
     * Get the current application version (e.g. "1.2.0").
     */
    public static function current(): string
    {
        if (self::$cached !== null) {
            return self::$cached;
        }

        $versionFile = dirname(__DIR__, 2) . '/VERSION';
        if (is_readable($versionFile)) {
            $version = trim((string) file_get_contents($versionFile));
            if ($version !== '') {
                return self::$cached = $version;
            }
        }

        return self::$cached = 'unknown';
    }
}
