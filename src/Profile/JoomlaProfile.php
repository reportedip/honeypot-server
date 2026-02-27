<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Profile;

/**
 * Joomla CMS profile.
 *
 * Emulates Joomla 4.4.2 URL structure, headers, and behaviour.
 */
class JoomlaProfile extends CmsProfile
{
    public function getName(): string
    {
        return 'joomla';
    }

    public function getLoginPath(): string
    {
        return '/administrator';
    }

    public function getAdminPath(): string
    {
        return '/administrator/';
    }

    /**
     * @return string[]
     */
    public function getApiPaths(): array
    {
        return [
            '/api/',
        ];
    }

    /**
     * @return array<string, string>
     */
    public function getDefaultHeaders(): array
    {
        return [
            'X-Content-Encoded-By' => 'Joomla! 4.4',
            'X-Powered-By'         => 'PHP/8.2.14',
        ];
    }

    public function getVersion(): string
    {
        return '4.4.2';
    }

    /**
     * @return string[]
     */
    public function getVulnerabilityPaths(): array
    {
        return [
            '/administrator/manifests/files/joomla.xml',
            '/configuration.php.bak',
            '/components/com_fabrik/',
            '/components/com_fields/',
            '/libraries/joomla/',
            '/plugins/',
        ];
    }

    public function getTemplatePath(): string
    {
        return 'joomla';
    }

    public function matchRoute(string $path, string $method, array $queryParams = []): string
    {
        // Administrator login / admin area
        if ($path === '/administrator' || str_starts_with($path, '/administrator/')) {
            // Joomla admin login is the admin area entry point
            if ($path === '/administrator' || $path === '/administrator/' || $path === '/administrator/index.php') {
                return 'login';
            }
            return 'admin';
        }

        // API
        if (str_starts_with($path, '/api/') || $path === '/api') {
            return 'api';
        }

        // Search
        if (str_starts_with($path, '/search') || str_contains($path, 'option=com_search')
            || str_contains($path, 'option=com_finder')) {
            return 'search';
        }

        // Contact form
        if (str_contains($path, 'option=com_contact') || $path === '/contact'
            || $path === '/contact/') {
            return 'contact';
        }

        // User registration
        if (str_contains($path, 'option=com_users') && str_contains($path, 'view=registration')) {
            return 'register';
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

        // Home page
        if ($path === '/' || $path === '' || $path === '/index.php') {
            return 'home';
        }

        // Featured content view
        if (isset($queryParams['option']) && $queryParams['option'] === 'com_content'
            && isset($queryParams['view']) && $queryParams['view'] === 'featured') {
            return 'home';
        }

        // AI-generated content: /blog/slug
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
            'site_name'      => 'My Joomla Site',
            'site_url'       => '',
            'joomla_version' => $this->getVersion(),
            'template'       => 'cassiopeia',
            'language'       => 'en-GB',
            'admin_email'    => 'admin@example.com',
        ];
    }
}
