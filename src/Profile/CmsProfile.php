<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Profile;

/**
 * Abstract base class for CMS profiles.
 *
 * Each profile defines the URL patterns, headers, templates, and
 * vulnerability paths that make the honeypot behave like a specific CMS.
 */
abstract class CmsProfile
{
    protected string $siteUrl = '';

    /**
     * Set the site URL derived from the current request.
     */
    public function setSiteUrl(string $url): void
    {
        $this->siteUrl = rtrim($url, '/');
    }

    /**
     * Get the site URL.
     */
    public function getSiteUrl(): string
    {
        return $this->siteUrl;
    }

    /**
     * Get the CMS identifier name (lowercase).
     */
    abstract public function getName(): string;

    /**
     * Get the primary login page path.
     */
    abstract public function getLoginPath(): string;

    /**
     * Get the admin area base path.
     */
    abstract public function getAdminPath(): string;

    /**
     * Get paths that expose API endpoints.
     *
     * @return string[]
     */
    abstract public function getApiPaths(): array;

    /**
     * Get default HTTP headers to include in every response.
     *
     * @return array<string, string>
     */
    abstract public function getDefaultHeaders(): array;

    /**
     * Get known vulnerability / enumeration paths.
     *
     * @return string[]
     */
    abstract public function getVulnerabilityPaths(): array;

    /**
     * Get the template subdirectory name for this CMS.
     */
    abstract public function getTemplatePath(): string;

    /**
     * Match a request path against this profile's known routes.
     *
     * @param array<string, string> $queryParams Query parameters from the request.
     * @return string Route type: 'login', 'admin', 'api', 'xmlrpc', 'vuln',
     *                'comment', 'search', 'register', 'contact', 'home', 'not_found', 'misc'
     */
    abstract public function matchRoute(string $path, string $method, array $queryParams = []): string;

    /**
     * Get a fake version string for this CMS.
     */
    abstract public function getVersion(): string;

    /**
     * Get CMS-specific fake data for templates.
     *
     * @return array<string, mixed>
     */
    abstract public function getTemplateData(): array;

    /**
     * Check whether a path starts with or equals any entry in a list.
     *
     * @param string   $path  The request path.
     * @param string[] $paths The list of known paths.
     */
    protected function pathMatchesAny(string $path, array $paths): bool
    {
        foreach ($paths as $known) {
            if ($path === $known || str_starts_with($path, $known)) {
                return true;
            }
        }

        return false;
    }
}
