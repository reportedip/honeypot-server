<?php

declare(strict_types=1);

/**
 * reportedip-honeypot-server Configuration
 *
 * Copy this file to config.php and adjust values.
 * Open the website in your browser to run the web installer.
 */

return [
    // API key for reportedip.de (64-character hex string)
    'api_key' => '',

    // reportedip.de API endpoint
    'api_url' => 'https://reportedip.de/wp-json/reportedip/v2/report',

    // CMS profile to emulate: 'wordpress', 'drupal', or 'joomla'
    'cms_profile' => 'wordpress',

    // Admin panel path (for honeypot management)
    'admin_path' => '/_hp_admin',

    // Bcrypt hash of the admin password (set by web installer)
    'admin_password_hash' => '',

    // SQLite database path
    'db_path' => __DIR__ . '/../data/honeypot.sqlite',

    // File cache directory
    'cache_path' => __DIR__ . '/../data/cache',

    // Cache TTL in seconds
    'cache_ttl' => 3600,

    // Max log entries per IP per minute (prevents log flooding)
    'rate_limit_per_ip' => 10,

    // Max API reports per minute
    'report_rate_limit' => 60,

    // Number of reports to send per batch
    'report_batch_size' => 10,

    // Queue processing mode: 'web' (automatic, no cron needed) or 'cron' (manual via cli.php)
    'queue_mode' => 'web',

    // Automatically whitelist the server's own IP
    'whitelist_own_ip' => true,

    // Trusted proxy CIDRs (Cloudflare ranges included by default)
    'trusted_proxies' => [
        // Cloudflare IPv4
        '173.245.48.0/20',
        '103.21.244.0/22',
        '103.22.200.0/22',
        '103.31.4.0/22',
        '141.101.64.0/18',
        '108.162.192.0/18',
        '190.93.240.0/20',
        '188.114.96.0/20',
        '197.234.240.0/22',
        '198.41.128.0/17',
        '162.158.0.0/15',
        '104.16.0.0/13',
        '104.24.0.0/14',
        '172.64.0.0/13',
        '131.0.72.0/22',
    ],

    // Enable debug mode (verbose error output)
    'debug' => false,

    // Number of days to keep log entries
    'log_retention_days' => 90,

    // Admin session lifetime in seconds (default 1 hour)
    'session_lifetime' => 3600,

    // Log human visitors (non-bot, non-attacker traffic)
    'log_human_visitors' => false,

    // Custom CA bundle path for cURL (leave empty for system default)
    'ca_bundle' => '',

    // ---------------------------------------------------------
    // AI Content Generation (optional, requires OpenAI API key)
    // ---------------------------------------------------------

    // OpenAI API key for AI content generation
    'openai_api_key' => '',

    // OpenAI API base URL (change for compatible providers)
    'openai_base_url' => 'https://api.openai.com/v1',

    // OpenAI model to use
    'openai_model' => 'gpt-4o-mini',

    // Default language for generated content ('en' or 'de')
    'content_language' => 'en',

    // Site identity (used in templates, feed, REST API)
    // Leave empty to use CMS-specific defaults
    'site_name' => '',
    'site_tagline' => '',

    // Default topic niche for content generation
    'content_niche' => '',

    // ---------------------------------------------------------
    // Self-Update System
    // ---------------------------------------------------------

    // Enable automatic updates (true = auto-apply, false = notify only)
    'auto_update' => true,

    // How often to check for updates in seconds (default: 3 hours)
    'update_check_interval' => 10800,
];
