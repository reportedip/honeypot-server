<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Trap\Data;

/**
 * Static registry of emulated WordPress themes with style.css generation.
 *
 * Includes default Twenty* themes and Avada as a popular premium theme
 * with known CVEs to attract scanner attention.
 */
final class WordPressThemeRegistry
{
    /** @var array<string, array{name: string, version: string, description: string, author: string, author_uri: string, requires: string, tested: string, requires_php: string, license: string, text_domain: string, tags: string[]}> */
    private const THEMES = [
        'twentytwentyfour' => [
            'name' => 'Twenty Twenty-Four',
            'version' => '1.0',
            'description' => 'Twenty Twenty-Four is designed to be flexible, versatile and applicable to any website.',
            'author' => 'the WordPress team',
            'author_uri' => 'https://wordpress.org',
            'requires' => '6.4',
            'tested' => '6.4.2',
            'requires_php' => '7.0',
            'license' => 'GNU General Public License v2 or later',
            'text_domain' => 'twentytwentyfour',
            'tags' => ['one-column', 'custom-colors', 'custom-menu', 'custom-logo', 'editor-style', 'featured-images', 'full-site-editing', 'block-patterns', 'wide-blocks', 'accessibility-ready', 'blog', 'portfolio'],
        ],
        'twentytwentythree' => [
            'name' => 'Twenty Twenty-Three',
            'version' => '1.3',
            'description' => 'Twenty Twenty-Three is designed to take advantage of the new design tools introduced in WordPress 6.1.',
            'author' => 'the WordPress team',
            'author_uri' => 'https://wordpress.org',
            'requires' => '6.1',
            'tested' => '6.4.2',
            'requires_php' => '5.9',
            'license' => 'GNU General Public License v2 or later',
            'text_domain' => 'twentytwentythree',
            'tags' => ['one-column', 'custom-colors', 'custom-menu', 'custom-logo', 'editor-style', 'featured-images', 'full-site-editing', 'block-patterns', 'wide-blocks', 'accessibility-ready'],
        ],
        'Avada' => [
            'name' => 'Avada',
            'version' => '7.11.4',
            'description' => 'Avada is the #1 selling WordPress theme on the market. It is a versatile and multi-purpose theme, with a powerful options network.',
            'author' => 'ThemeFusion',
            'author_uri' => 'https://theme-fusion.com',
            'requires' => '5.8',
            'tested' => '6.4.2',
            'requires_php' => '7.0',
            'license' => 'ThemeForest Regular License',
            'text_domain' => 'Avada',
            'tags' => ['multipurpose', 'responsive', 'business', 'portfolio', 'woocommerce', 'one-page', 'agency'],
        ],
    ];

    /**
     * Subdirectories that return 403 Forbidden for premium themes.
     */
    private const PROTECTED_DIRS = ['includes', 'framework', 'lib', 'vendor', 'admin'];

    /**
     * Get all registered themes.
     *
     * @return array<string, array{name: string, version: string, description: string, author: string, author_uri: string, requires: string, tested: string, requires_php: string, license: string, text_domain: string, tags: string[]}>
     */
    public static function getThemes(): array
    {
        return self::THEMES;
    }

    /**
     * Check if a theme slug is registered.
     */
    public static function hasTheme(string $slug): bool
    {
        return isset(self::THEMES[$slug]);
    }

    /**
     * Get metadata for a specific theme.
     *
     * @return array{name: string, version: string, description: string, author: string, author_uri: string, requires: string, tested: string, requires_php: string, license: string, text_domain: string, tags: string[]}|null
     */
    public static function getTheme(string $slug): ?array
    {
        return self::THEMES[$slug] ?? null;
    }

    /**
     * Generate a realistic WordPress theme style.css with standard header comment.
     */
    public static function generateStyleCss(string $slug): ?string
    {
        $theme = self::THEMES[$slug] ?? null;
        if ($theme === null) {
            return null;
        }

        $tags = implode(', ', $theme['tags']);

        return <<<CSS
/*
Theme Name: {$theme['name']}
Theme URI: {$theme['author_uri']}
Author: {$theme['author']}
Author URI: {$theme['author_uri']}
Description: {$theme['description']}
Requires at least: {$theme['requires']}
Tested up to: {$theme['tested']}
Requires PHP: {$theme['requires_php']}
Version: {$theme['version']}
License: {$theme['license']}
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Text Domain: {$theme['text_domain']}
Tags: {$tags}
*/
CSS;
    }

    /**
     * Determine the appropriate response for a theme subdirectory request.
     *
     * @return array{status: int, content_type: string, body: string}|null Null if not a known theme.
     */
    public static function getThemeDirectoryResponse(string $slug, string $subpath): ?array
    {
        if (!isset(self::THEMES[$slug])) {
            return null;
        }

        $subpath = trim($subpath, '/');

        // Root directory: "Silence is golden"
        if ($subpath === '') {
            return [
                'status' => 200,
                'content_type' => 'text/html; charset=UTF-8',
                'body' => '',
            ];
        }

        // Protected subdirectories: 403
        $firstSegment = explode('/', $subpath)[0];
        if (in_array($firstSegment, self::PROTECTED_DIRS, true)) {
            return [
                'status' => 403,
                'content_type' => 'text/html; charset=UTF-8',
                'body' => self::getForbiddenPage(),
            ];
        }

        // CSS/JS assets under assets/ directory
        if (str_starts_with($subpath, 'assets/') && preg_match('/\.(css|js)$/i', $subpath, $m)) {
            $ext = strtolower($m[1]);
            $theme = self::THEMES[$slug];
            $contentType = $ext === 'css' ? 'text/css; charset=UTF-8' : 'application/javascript; charset=UTF-8';
            $body = "/*!\n * {$theme['name']} v{$theme['version']}\n * (c) {$theme['author']}\n */\n";

            return [
                'status' => 200,
                'content_type' => $contentType,
                'body' => $body,
            ];
        }

        // Other subdirectories: empty 200 (generic "Silence is golden")
        if (str_ends_with($subpath, '/') || !str_contains(basename($subpath), '.')) {
            return [
                'status' => 200,
                'content_type' => 'text/html; charset=UTF-8',
                'body' => '',
            ];
        }

        return null;
    }

    /**
     * Generate minimal CSS content for a theme asset.
     */
    public static function generateMinimalAssetCss(string $slug): ?string
    {
        $theme = self::THEMES[$slug] ?? null;
        if ($theme === null) {
            return null;
        }

        return "/*!\n * {$theme['name']} v{$theme['version']}\n * (c) {$theme['author']}\n */\n";
    }

    private static function getForbiddenPage(): string
    {
        return <<<'HTML'
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.58 (Ubuntu) Server at localhost Port 80</address>
</body></html>
HTML;
    }
}
