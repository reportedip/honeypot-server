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

        // The plugins below advertise versions that are vulnerable to
        // widely exploited 2026 CVEs. Scanners that fingerprint the
        // Stable tag will flag the site as exploitable and proceed with
        // their exploit attempts, which the detection pipeline captures.

        // CVE-2026-8206: password reset account takeover (500k installs)
        'kirki' => [
            'name' => 'Kirki Customizer Framework',
            'version' => '4.2.0',
            'requires' => '5.2',
            'tested' => '6.4.2',
            'requires_php' => '7.4',
            'author' => 'Themeum',
            'author_uri' => 'https://kirki.org/',
            'description' => 'The most advanced WordPress Customizer Framework. Providing streamlined solutions for theme developers.',
            'tags' => ['customizer', 'framework', 'theme options', 'options framework', 'fields'],
        ],
        // CVE-2026-8181: REST API authentication bypass (200k installs)
        'burst-statistics' => [
            'name' => 'Burst Statistics - Privacy-Friendly Analytics',
            'version' => '2.0.5',
            'requires' => '6.0',
            'tested' => '6.4.2',
            'requires_php' => '7.4',
            'author' => 'Really Simple Plugins',
            'author_uri' => 'https://burst-statistics.com/',
            'description' => 'Self-hosted and privacy-friendly analytics dashboard for WordPress. GDPR compliant statistics without cookies.',
            'tags' => ['analytics', 'statistics', 'privacy', 'GDPR', 'stats'],
        ],
        // CVE-2026-19632: plaintext password-reset key disclosure (400k installs)
        'translatepress-multilingual' => [
            'name' => 'Translate Multilingual sites - TranslatePress',
            'version' => '3.3.1',
            'requires' => '5.0',
            'tested' => '6.4.2',
            'requires_php' => '7.0',
            'author' => 'Cozmoslabs, Razvan Mocanu, Madalin Ungureanu',
            'author_uri' => 'https://translatepress.com/',
            'description' => 'Translate your WordPress website directly from the front-end, with full support for WooCommerce and page builders.',
            'tags' => ['translate', 'translation', 'multilingual', 'localization', 'i18n'],
        ],
        // CVE-2026-19598: unauthenticated privilege escalation (100k installs)
        'pods' => [
            'name' => 'Pods - Custom Content Types and Fields',
            'version' => '3.3.9',
            'requires' => '6.0',
            'tested' => '6.4.2',
            'requires_php' => '7.2',
            'author' => 'Pods Framework Team',
            'author_uri' => 'https://pods.io/',
            'description' => 'Pods is a framework for creating, managing, and deploying customized content types and fields.',
            'tags' => ['custom post types', 'custom fields', 'taxonomies', 'content types', 'framework'],
        ],
        // CVE-2026-82222: PHP object injection via unserialize (CVSS 10.0)
        'give' => [
            'name' => 'GiveWP - Donation Plugin and Fundraising Platform',
            'version' => '4.16.7',
            'requires' => '6.3',
            'tested' => '6.4.2',
            'requires_php' => '7.4',
            'author' => 'GiveWP',
            'author_uri' => 'https://givewp.com/',
            'description' => 'The most robust, flexible, and intuitive way to accept donations on WordPress.',
            'tags' => ['donations', 'donate', 'fundraising', 'crowdfunding', 'payments'],
        ],
        // CVE-2026-3300: unauthenticated remote code execution (CVSS 9.8)
        'everest-forms' => [
            'name' => 'Everest Forms - Contact Form, Quiz, Survey & Newsletter',
            'version' => '1.9.12',
            'requires' => '5.2',
            'tested' => '6.4.2',
            'requires_php' => '7.2',
            'author' => 'WPEverest',
            'author_uri' => 'https://wpeverest.com/',
            'description' => 'Drag and drop contact form builder to create simple to complex forms with ease.',
            'tags' => ['contact form', 'form builder', 'forms', 'survey', 'drag and drop'],
        ],
        // CVE-2026-3844: SSRF via gravatar fetch (400k+ installs)
        'breeze' => [
            'name' => 'Breeze - WordPress Cache Plugin',
            'version' => '2.1.13',
            'requires' => '5.3',
            'tested' => '6.4.2',
            'requires_php' => '7.0',
            'author' => 'Cloudways',
            'author_uri' => 'https://www.cloudways.com/',
            'description' => 'Breeze is a WordPress cache plugin with extensive options to speed up your website.',
            'tags' => ['cache', 'performance', 'speed', 'optimization', 'minify'],
        ],
        // CVE-2024-28000: unauthenticated admin account takeover (6M+ installs)
        'litespeed-cache' => [
            'name' => 'LiteSpeed Cache',
            'version' => '6.3',
            'requires' => '5.3',
            'tested' => '6.4.2',
            'requires_php' => '7.0',
            'author' => 'LiteSpeed Technologies',
            'author_uri' => 'https://www.litespeedtech.com/',
            'description' => 'High-performance page caching and site optimization from LiteSpeed.',
            'tags' => ['cache', 'performance', 'optimization', 'pagespeed', 'core web vitals'],
        ],
        // CVE-2025-9501: unauthenticated remote code execution (1M+ installs)
        'w3-total-cache' => [
            'name' => 'W3 Total Cache',
            'version' => '2.8.7',
            'requires' => '5.3',
            'tested' => '6.4.2',
            'requires_php' => '8.0',
            'author' => 'BoldGrid',
            'author_uri' => 'https://www.boldgrid.com/w3-total-cache/',
            'description' => 'Search Engine (SEO) and performance optimization through caching for WordPress.',
            'tags' => ['cache', 'performance', 'pagespeed', 'cdn', 'optimization'],
        ],
        // CVE-2026-1357: unauthenticated arbitrary file upload to RCE (900k installs)
        'wpvivid-backuprestore' => [
            'name' => 'Migration, Backup, Staging - WPvivid Backup & Migration',
            'version' => '0.9.123',
            'requires' => '4.5',
            'tested' => '6.4.2',
            'requires_php' => '5.6',
            'author' => 'WPvivid Team',
            'author_uri' => 'https://wpvivid.com/',
            'description' => 'Migrate, back up and restore your WordPress site, with scheduled backups to remote storage.',
            'tags' => ['backup', 'migration', 'restore', 'staging', 'clone'],
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
