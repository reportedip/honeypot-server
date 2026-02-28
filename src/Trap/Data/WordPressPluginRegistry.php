<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Trap\Data;

/**
 * Static registry of emulated WordPress plugins with readme.txt generation.
 *
 * Versions are deliberately 1-2 minor versions behind current to appear
 * as a real but slightly outdated WordPress installation.
 */
final class WordPressPluginRegistry
{
    /** @var array<string, array{name: string, version: string, requires: string, tested: string, requires_php: string, author: string, author_uri: string, description: string, tags: string[]}> */
    private const PLUGINS = [
        'contact-form-7' => [
            'name' => 'Contact Form 7',
            'version' => '5.8.4',
            'requires' => '6.2',
            'tested' => '6.4.2',
            'requires_php' => '7.4',
            'author' => 'Takayuki Miyoshi',
            'author_uri' => 'https://ideasilo.wordpress.com/',
            'description' => 'Just another contact form plugin. Simple but flexible.',
            'tags' => ['contact', 'form', 'contact form', 'feedback', 'email'],
        ],
        'wordpress-seo' => [
            'name' => 'Yoast SEO',
            'version' => '21.6',
            'requires' => '6.3',
            'tested' => '6.4.2',
            'requires_php' => '7.2.5',
            'author' => 'Team Yoast',
            'author_uri' => 'https://yoast.com/',
            'description' => 'The first true all-in-one SEO solution for WordPress, including on-page content analysis, XML sitemaps and much more.',
            'tags' => ['SEO', 'XML sitemap', 'google search console', 'content analysis', 'readability'],
        ],
        'elementor' => [
            'name' => 'Elementor',
            'version' => '3.18.3',
            'requires' => '6.0',
            'tested' => '6.4.2',
            'requires_php' => '7.4',
            'author' => 'Elementor.com',
            'author_uri' => 'https://elementor.com/',
            'description' => 'The Elementor Website Builder has it all: drag and drop page builder, pixel perfect design, mobile responsive editing, and more.',
            'tags' => ['page builder', 'editor', 'landing page', 'drag-and-drop', 'elementor'],
        ],
        'woocommerce' => [
            'name' => 'WooCommerce',
            'version' => '8.3.1',
            'requires' => '6.4',
            'tested' => '6.4.2',
            'requires_php' => '7.4',
            'author' => 'Automattic',
            'author_uri' => 'https://woocommerce.com/',
            'description' => 'An eCommerce toolkit that helps you sell anything. Beautifully.',
            'tags' => ['e-commerce', 'store', 'sales', 'sell', 'woo'],
        ],
        'akismet' => [
            'name' => 'Akismet Anti-Spam',
            'version' => '5.3',
            'requires' => '5.8',
            'tested' => '6.4.2',
            'requires_php' => '5.6.20',
            'author' => 'Automattic',
            'author_uri' => 'https://automattic.com/wordpress-plugins/',
            'description' => 'Used by millions, Akismet is quite possibly the best way in the world to protect your blog from spam.',
            'tags' => ['akismet', 'anti-spam', 'antispam', 'comments', 'spam'],
        ],
        'classic-editor' => [
            'name' => 'Classic Editor',
            'version' => '1.6.3',
            'requires' => '4.9',
            'tested' => '6.4.2',
            'requires_php' => '5.2.4',
            'author' => 'WordPress Contributors',
            'author_uri' => 'https://github.com/WordPress/classic-editor/',
            'description' => 'Enables the previous "classic" editor and the old-style Edit Post screen with TinyMCE, Meta Boxes, etc.',
            'tags' => ['gutenberg', 'disable', 'classic', 'editor', 'TinyMCE'],
        ],
        'wordfence' => [
            'name' => 'Wordfence Security',
            'version' => '7.11.0',
            'requires' => '3.9',
            'tested' => '6.4.2',
            'requires_php' => '7.0',
            'author' => 'Wordfence',
            'author_uri' => 'https://www.wordfence.com/',
            'description' => 'Wordfence Security - Anti-virus, Firewall and Malware Scan.',
            'tags' => ['firewall', 'security', 'malware', 'virus', 'wordfence'],
        ],
        'revslider' => [
            'name' => 'Slider Revolution',
            'version' => '6.6.18',
            'requires' => '5.0',
            'tested' => '6.4.2',
            'requires_php' => '7.0',
            'author' => 'ThemePunch',
            'author_uri' => 'https://www.themepunch.com/',
            'description' => 'Slider Revolution - Premium responsive slider.',
            'tags' => ['slider', 'revolution', 'carousel', 'responsive', 'image slider'],
        ],
        'advanced-custom-fields' => [
            'name' => 'Advanced Custom Fields',
            'version' => '6.2.4',
            'requires' => '5.8',
            'tested' => '6.4.2',
            'requires_php' => '7.0',
            'author' => 'WP Engine',
            'author_uri' => 'https://www.advancedcustomfields.com/',
            'description' => 'Customize WordPress with powerful, professional and intuitive fields.',
            'tags' => ['acf', 'advanced custom fields', 'custom fields', 'meta', 'fields'],
        ],
        'wpforms-lite' => [
            'name' => 'WPForms Lite',
            'version' => '1.8.5',
            'requires' => '5.5',
            'tested' => '6.4.2',
            'requires_php' => '7.0',
            'author' => 'WPForms',
            'author_uri' => 'https://wpforms.com/',
            'description' => 'Beginner friendly WordPress contact form plugin. Use our Drag & Drop form builder to create your WordPress forms.',
            'tags' => ['contact form', 'contact', 'form', 'survey', 'free'],
        ],
    ];

    /**
     * Get all registered plugins.
     *
     * @return array<string, array{name: string, version: string, requires: string, tested: string, requires_php: string, author: string, author_uri: string, description: string, tags: string[]}>
     */
    public static function getPlugins(): array
    {
        return self::PLUGINS;
    }

    /**
     * Check if a plugin slug is registered.
     */
    public static function hasPlugin(string $slug): bool
    {
        return isset(self::PLUGINS[$slug]);
    }

    /**
     * Get metadata for a specific plugin.
     *
     * @return array{name: string, version: string, requires: string, tested: string, requires_php: string, author: string, author_uri: string, description: string, tags: string[]}|null
     */
    public static function getPlugin(string $slug): ?array
    {
        return self::PLUGINS[$slug] ?? null;
    }

    /**
     * Generate a realistic WordPress-format readme.txt for a plugin.
     */
    public static function generateReadmeTxt(string $slug): ?string
    {
        $plugin = self::PLUGINS[$slug] ?? null;
        if ($plugin === null) {
            return null;
        }

        $tags = implode(', ', $plugin['tags']);
        $name = $plugin['name'];
        $version = $plugin['version'];
        $author = $plugin['author'];
        $authorUri = $plugin['author_uri'];
        $requires = $plugin['requires'];
        $tested = $plugin['tested'];
        $requiresPhp = $plugin['requires_php'];
        $description = $plugin['description'];

        // Generate a plausible older version for changelog
        $parts = explode('.', $version);
        $prevMinor = max(0, (int)end($parts) - 1);
        $prevParts = $parts;
        $prevParts[count($prevParts) - 1] = (string)$prevMinor;
        $prevVersion = implode('.', $prevParts);

        return <<<README
=== {$name} ===
Contributors: {$slug}
Tags: {$tags}
Requires at least: {$requires}
Tested up to: {$tested}
Requires PHP: {$requiresPhp}
Stable tag: {$version}
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

{$description}

== Description ==

{$description}

For more information, visit [{$name}]({$authorUri}).

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/{$slug}` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. Use the Settings screen to configure the plugin.

== Frequently Asked Questions ==

= How do I get started? =

After activating the plugin, go to Settings and follow the setup wizard.

= Where can I find documentation? =

Visit the official documentation at {$authorUri}.

== Changelog ==

= {$version} =
* Security: Fixed potential vulnerability in input handling
* Improved compatibility with WordPress {$tested}
* Various bug fixes and performance improvements

= {$prevVersion} =
* Bug fixes and stability improvements
* Updated translations

== Upgrade Notice ==

= {$version} =
This version includes security fixes. Please update immediately.
README;
    }

    /**
     * Generate minimal CSS content for a plugin stylesheet.
     */
    public static function generateMinimalCss(string $slug): ?string
    {
        $plugin = self::PLUGINS[$slug] ?? null;
        if ($plugin === null) {
            return null;
        }

        return "/*!\n * {$plugin['name']} v{$plugin['version']}\n * (c) {$plugin['author']}\n * License: GPLv2+\n */\n";
    }

    /**
     * Generate minimal JS content for a plugin script.
     */
    public static function generateMinimalJs(string $slug): ?string
    {
        $plugin = self::PLUGINS[$slug] ?? null;
        if ($plugin === null) {
            return null;
        }

        return "/*!\n * {$plugin['name']} v{$plugin['version']}\n * (c) {$plugin['author']}\n */\n\"use strict\";\n";
    }
}
