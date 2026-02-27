<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Core;

use ReportedIp\Honeypot\Profile\CmsProfile;

/**
 * Request router.
 *
 * Routes incoming requests to the appropriate trap handler based on
 * the active CMS profile's URL patterns.
 */
final class Router
{
    public function __construct(
        private readonly CmsProfile $profile,
        private readonly Config $config,
    ) {}

    /**
     * Determine which trap should handle the given request.
     *
     * @return array{trap: string, params: array<string, mixed>}
     */
    public function route(Request $request): array
    {
        $path = $request->getPath();
        $method = $request->getMethod();

        // Check honeypot admin panel path first
        if ($this->isAdminPath($request)) {
            return ['trap' => 'admin', 'params' => []];
        }

        // Delegate to the CMS profile's route matching
        $routeType = $this->profile->matchRoute($path, $method, $request->getQueryParams());

        return match ($routeType) {
            'login'    => ['trap' => 'login', 'params' => []],
            'admin'    => ['trap' => 'cms_admin', 'params' => []],
            'api'      => ['trap' => 'api', 'params' => []],
            'xmlrpc'   => ['trap' => 'xmlrpc', 'params' => []],
            'vuln'     => ['trap' => 'vulnerability', 'params' => ['path' => $path]],
            'comment'  => ['trap' => 'comment', 'params' => []],
            'search'   => ['trap' => 'search', 'params' => ['query' => $request->getQueryParam('s') ?? '']],
            'register' => ['trap' => 'register', 'params' => []],
            'contact'  => ['trap' => 'contact', 'params' => []],
            'home'     => ['trap' => 'home', 'params' => []],
            'misc'     => ['trap' => 'misc', 'params' => ['path' => $path]],
            'content'  => ['trap' => 'content', 'params' => ['path' => $path]],
            default    => ['trap' => 'not_found', 'params' => ['path' => $path]],
        };
    }

    /**
     * Check whether the request targets the honeypot admin panel.
     */
    public function isAdminPath(Request $request): bool
    {
        $adminPath = $this->config->get('admin_path', '/_hp_admin');
        $path = $request->getPath();

        return $path === $adminPath || str_starts_with($path, $adminPath . '/');
    }
}
