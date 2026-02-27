<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;

/**
 * Detects scanning of CMS admin directories and sub-paths.
 *
 * Covers WordPress admin setup/maintenance paths, admin-ajax without action,
 * direct access to wp-admin includes/network, Drupal admin paths
 * (config, modules, people), and Joomla administrator component/module paths.
 */
final class AdminDirectoryScanningAnalyzer implements AnalyzerInterface
{
    /** WordPress admin sub-paths that indicate scanning or exploitation. */
    private const WP_ADMIN_SENSITIVE_PATHS = [
        '#/wp-admin/install\.php#i' => ['WordPress install.php probe', 70],
        '#/wp-admin/setup-config\.php#i' => ['WordPress setup-config.php probe', 75],
        '#/wp-admin/upgrade\.php#i' => ['WordPress upgrade.php probe', 65],
        '#/wp-admin/maint/repair\.php#i' => ['WordPress database repair probe', 70],
        '#/wp-admin/import\.php#i' => ['WordPress import tool probe', 55],
        '#/wp-admin/export\.php#i' => ['WordPress export tool probe', 55],
        '#/wp-admin/includes/#i' => ['Direct access to wp-admin/includes/', 65],
        '#/wp-admin/network/#i' => ['WordPress multisite network admin probe', 60],
    ];

    /** Drupal admin paths that indicate scanning. */
    private const DRUPAL_ADMIN_PATHS = [
        '#^/admin/config#i' => ['Drupal admin config access', 55],
        '#^/admin/modules#i' => ['Drupal admin modules access', 60],
        '#^/admin/people#i' => ['Drupal admin people/users access', 60],
    ];

    /** Joomla administrator paths that indicate scanning. */
    private const JOOMLA_ADMIN_PATHS = [
        '#/administrator/components/#i' => ['Joomla administrator components scanning', 60],
        '#/administrator/modules/#i' => ['Joomla administrator modules scanning', 60],
    ];

    public function getName(): string
    {
        return 'AdminDirectoryScanning';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $path = $request->getPath();

        if ($path === '' || $path === '/') {
            return null;
        }

        $findings = [];
        $maxScore = 0;

        // Check WordPress admin sensitive paths
        $this->checkPathPatterns($path, self::WP_ADMIN_SENSITIVE_PATHS, $findings, $maxScore);

        // Check admin-ajax.php without action parameter
        $this->checkAdminAjaxNoAction($request, $findings, $maxScore);

        // Check Drupal admin paths
        $this->checkPathPatterns($path, self::DRUPAL_ADMIN_PATHS, $findings, $maxScore);

        // Check Joomla administrator paths
        $this->checkPathPatterns($path, self::JOOMLA_ADMIN_PATHS, $findings, $maxScore);

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'Admin directory scanning detected: %s (path: %s)',
            implode('; ', array_slice(array_unique($findings), 0, 3)),
            substr($path, 0, 200)
        );

        return new DetectionResult([32, 15], $comment, $maxScore, $this->getName());
    }

    /**
     * @param array<string, array{0: string, 1: int}> $patterns
     */
    private function checkPathPatterns(string $path, array $patterns, array &$findings, int &$maxScore): void
    {
        foreach ($patterns as $pattern => [$description, $score]) {
            if (preg_match($pattern, $path)) {
                $findings[] = $description;
                $maxScore = max($maxScore, $score);
            }
        }
    }

    private function checkAdminAjaxNoAction(Request $request, array &$findings, int &$maxScore): void
    {
        $path = $request->getPath();

        if (!preg_match('#/wp-admin/admin-ajax\.php#i', $path)) {
            return;
        }

        // GET request to admin-ajax.php without an action parameter is scanning behavior
        if ($request->isGet()) {
            $action = $request->getQueryParam('action');
            if ($action === null || $action === '') {
                $findings[] = 'admin-ajax.php GET without action parameter (scanning)';
                $maxScore = max($maxScore, 50);
            }
        }
    }
}
