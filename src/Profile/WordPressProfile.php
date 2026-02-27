<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Profile;

/**
 * WordPress CMS profile.
 *
 * Emulates WordPress 6.4.2 URL structure, headers, and behaviour.
 */
class WordPressProfile extends CmsProfile
{
    public function getName(): string
    {
        return 'wordpress';
    }

    public function getLoginPath(): string
    {
        return '/wp-login.php';
    }

    public function getAdminPath(): string
    {
        return '/wp-admin/';
    }

    /**
     * @return string[]
     */
    public function getApiPaths(): array
    {
        return [
            '/wp-json/',
            '/xmlrpc.php',
        ];
    }

    /**
     * @return array<string, string>
     */
    public function getDefaultHeaders(): array
    {
        return [
            'X-Pingback'              => '/xmlrpc.php',
            'Link'                     => '</wp-json/>; rel="https://api.w.org/"',
            'X-Content-Type-Options'   => 'nosniff',
            'Server'                   => 'Apache/2.4.58 (Ubuntu)',
        ];
    }

    public function getVersion(): string
    {
        return '6.4.2';
    }

    /**
     * @return string[]
     */
    public function getVulnerabilityPaths(): array
    {
        return [
            '/wp-content/plugins/revslider/',
            '/wp-config.php.bak',
            '/readme.html',
            '/wp-content/debug.log',
            '/wp-json/wp/v2/users',
            '/?author=1',
            '/wp-content/uploads/',
            '/wp-includes/',
        ];
    }

    public function getTemplatePath(): string
    {
        return 'wordpress';
    }

    public function matchRoute(string $path, string $method, array $queryParams = []): string
    {
        // Login / registration
        if ($path === '/wp-login.php' || str_starts_with($path, '/wp-login.php')) {
            if (str_contains($path, 'action=register')) {
                return 'register';
            }
            return 'login';
        }

        // XML-RPC
        if ($path === '/xmlrpc.php') {
            return 'xmlrpc';
        }

        // REST API (path-based and ?rest_route= fallback)
        if (str_starts_with($path, '/wp-json/') || $path === '/wp-json') {
            return 'api';
        }
        if (isset($queryParams['rest_route'])) {
            return 'api';
        }

        // Misc WordPress files (robots.txt, feed, wp-cron, sitemap, jquery, index.php)
        if ($path === '/robots.txt' || $path === '/sitemap.xml') {
            return 'misc';
        }
        if ($path === '/feed/' || $path === '/feed') {
            return 'misc';
        }
        if ($path === '/wp-cron.php') {
            return 'misc';
        }
        if ($path === '/wp-includes/js/jquery/jquery.min.js') {
            return 'misc';
        }

        // Admin area
        if (str_starts_with($path, '/wp-admin')) {
            return 'admin';
        }

        // Comment posting
        if ($path === '/wp-comments-post.php') {
            return 'comment';
        }

        // Search (check query params, not the path)
        if ($method === 'GET' && isset($queryParams['s'])) {
            return 'search';
        }

        // Author enumeration (check query params for ?author=)
        if (isset($queryParams['author']) || preg_match('#^/author/.+#', $path)) {
            return 'vuln';
        }

        // Vulnerability paths
        foreach ($this->getVulnerabilityPaths() as $vulnPath) {
            if ($path === $vulnPath || str_starts_with($path, $vulnPath)) {
                return 'vuln';
            }
        }

        // Contact form
        if ($path === '/contact' || $path === '/contact-us' || $path === '/contact/') {
            return 'contact';
        }

        // Home page (also /index.php like real WP)
        if ($path === '/' || $path === '' || $path === '/index.php') {
            return 'home';
        }

        // AI-generated content pages: /YYYY/MM/slug/
        if (preg_match('#^/\d{4}/\d{2}/[\w-]+/?$#', $path)) {
            return 'content';
        }

        return 'not_found';
    }

    /**
     * @return array<string, mixed>
     */
    public function getTemplateData(): array
    {
        return [
            'site_name'   => 'My WordPress Site',
            'site_url'    => '',
            'wp_version'  => $this->getVersion(),
            'theme'       => 'twentytwentyfour',
            'tagline'     => 'Just another WordPress site',
            'admin_email' => 'admin@example.com',
            'language'    => 'en-US',
        ];
    }
}
