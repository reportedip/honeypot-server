<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Profile;

/**
 * Drupal CMS profile.
 *
 * Emulates Drupal 10.2.2 URL structure, headers, and behaviour.
 */
class DrupalProfile extends CmsProfile
{
    public function getName(): string
    {
        return 'drupal';
    }

    public function getLoginPath(): string
    {
        return '/user/login';
    }

    public function getAdminPath(): string
    {
        return '/admin/';
    }

    /**
     * @return string[]
     */
    public function getApiPaths(): array
    {
        return [
            '/jsonapi/',
        ];
    }

    /**
     * @return array<string, string>
     */
    public function getDefaultHeaders(): array
    {
        return [
            'X-Generator'  => 'Drupal 10 (https://www.drupal.org)',
            'X-Drupal-Cache' => 'HIT',
            'X-Powered-By'  => 'PHP/8.2.14',
        ];
    }

    public function getVersion(): string
    {
        return '10.2.2';
    }

    /**
     * @return string[]
     */
    public function getVulnerabilityPaths(): array
    {
        return [
            '/CHANGELOG.txt',
            '/sites/default/settings.php',
            '/user/1',
            '/sites/all/modules/',
            '/update.php',
            '/install.php',
            '/core/install.php',
        ];
    }

    public function getTemplatePath(): string
    {
        return 'drupal';
    }

    public function matchRoute(string $path, string $method, array $queryParams = []): string
    {
        // Login
        if ($path === '/user/login' || $path === '/user/login/') {
            return 'login';
        }

        // Registration
        if ($path === '/user/register' || $path === '/user/register/') {
            return 'register';
        }

        // JSON API
        if (str_starts_with($path, '/jsonapi/') || $path === '/jsonapi') {
            return 'api';
        }

        // Admin area
        if (str_starts_with($path, '/admin/') || $path === '/admin') {
            return 'admin';
        }

        // Search
        if (str_starts_with($path, '/search/') || $path === '/search') {
            return 'search';
        }

        // Comment posting
        if (str_starts_with($path, '/comment/') && $method === 'POST') {
            return 'comment';
        }

        // Contact form
        if ($path === '/contact' || $path === '/contact/' || str_starts_with($path, '/contact/')) {
            return 'contact';
        }

        // User profile enumeration
        if (preg_match('#^/user/\d+$#', $path)) {
            return 'vuln';
        }

        // Vulnerability paths
        foreach ($this->getVulnerabilityPaths() as $vulnPath) {
            if ($path === $vulnPath || str_starts_with($path, $vulnPath)) {
                return 'vuln';
            }
        }

        // Misc files
        if ($path === '/robots.txt' || $path === '/sitemap.xml') {
            return 'misc';
        }
        if ($path === '/rss.xml' || $path === '/feed') {
            return 'misc';
        }

        // Home page
        if ($path === '/' || $path === '' || $path === '/node') {
            return 'home';
        }

        // AI-generated content: /node/ID (ID >= 10) or /blog/slug
        if (preg_match('#^/node/(\d+)$#', $path, $m) && (int) $m[1] >= 10) {
            return 'content';
        }
        if (preg_match('#^/blog/[\w-]+/?$#', $path)) {
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
            'site_name'    => 'My Drupal Site',
            'site_url'     => $this->getSiteUrl(),
            'drupal_version' => $this->getVersion(),
            'theme'        => 'olivero',
            'language'     => 'en',
            'admin_email'  => 'admin@example.com',
        ];
    }
}
