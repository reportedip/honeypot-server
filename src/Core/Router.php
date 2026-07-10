<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Core;

use ReportedIp\Honeypot\Detection\PatternLibrary;
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

        // Cross-CMS bait paths (source leaks, DB-admin panels, info endpoints,
        // webshells) are handled before the profile so they behave identically
        // regardless of the emulated CMS.
        $baitTrap = $this->matchBaitTrap($request);
        if ($baitTrap !== null) {
            return ['trap' => $baitTrap, 'params' => ['path' => $path]];
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
     * Match cross-CMS bait paths that are served identically for every profile.
     *
     * @return string|null Trap name, or null if the path is not a bait path.
     */
    private function matchBaitTrap(Request $request): ?string
    {
        $path = $request->getPath();

        if ($path === '' || $path === '/') {
            return null;
        }

        // Source / secret disclosure: .env, .git, .svn metadata
        if (preg_match('#(?:^|/)\.env(\.[\w.-]+)?$#i', $path)
            || preg_match('#/\.git/(config|HEAD|index|logs/HEAD)$#i', $path)
            || preg_match('#/\.svn/(entries|wc\.db)$#i', $path)) {
            return 'source_leak';
        }

        // Database admin panels (checked before webshell so adminer.php lands here)
        if (preg_match('#/(phpmyadmin|phpMyAdmin|pma|myadmin|mysqladmin|dbadmin)(/|$)#i', $path)
            || preg_match('#/adminer(\.php)?$#i', $path)) {
            return 'db_admin';
        }

        // Server-info and application monitoring endpoints
        if (preg_match('#/server-(status|info)$#i', $path)
            || preg_match('#/actuator(/(env|health|info))?/?$#i', $path)) {
            return 'system_info';
        }

        // Known webshell filenames and disguised uploads
        $basename = strtolower(basename($path));
        if (in_array($basename, PatternLibrary::webshellFilenames(), true)
            || preg_match('#/(wp-content/uploads|uploads|images|media|files|tmp)/.*\.(php\d?|phtml|phar|pht)$#i', $path)
            || preg_match('#\.(jpg|jpeg|png|gif|pdf|txt|zip)\.(php\d?|phtml|phar|pht)$#i', $basename)) {
            return 'webshell';
        }

        return null;
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
