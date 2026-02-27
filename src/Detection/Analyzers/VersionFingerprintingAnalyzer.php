<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;

/**
 * Detects CMS version fingerprinting and information gathering attempts.
 *
 * Covers access to readme/license/changelog files, wp-includes scanning,
 * wp-admin CSS/JS access, version parameter probing, wp-includes image
 * scanning, and Drupal/Joomla version disclosure paths.
 */
final class VersionFingerprintingAnalyzer implements AnalyzerInterface
{
    /** WordPress version disclosure paths. */
    private const WP_VERSION_PATHS = [
        '#^/readme\.html$#i' => ['WordPress readme.html access', 55],
        '#^/license\.txt$#i' => ['WordPress license.txt access', 40],
        '#/wp-includes/version\.php#i' => ['Direct wp-includes/version.php access', 65],
    ];

    /** WordPress static asset scanning patterns. */
    private const WP_ASSET_SCANNING_PATHS = [
        '#/wp-includes/js/[^/]+\.js#i' => ['WordPress JS file scanning', 45],
        '#/wp-admin/css/[^/]+\.css#i' => ['WordPress admin CSS scanning', 50],
        '#/wp-admin/js/[^/]+\.js#i' => ['WordPress admin JS scanning', 50],
        '#/wp-includes/images/[^/]+#i' => ['WordPress images directory scanning', 45],
    ];

    /** Drupal version disclosure paths. */
    private const DRUPAL_VERSION_PATHS = [
        '#^/CHANGELOG\.txt$#i' => ['Drupal CHANGELOG.txt access', 55],
        '#^/core/CHANGELOG\.txt$#i' => ['Drupal core CHANGELOG.txt access', 55],
    ];

    /** Joomla version disclosure paths. */
    private const JOOMLA_VERSION_PATHS = [
        '#/administrator/manifests/files/joomla\.xml#i' => ['Joomla version manifest access', 55],
    ];

    public function getName(): string
    {
        return 'VersionFingerprinting';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $path = $request->getPath();
        $uri = $request->getUri();

        if ($path === '' || $path === '/') {
            return null;
        }

        $findings = [];
        $maxScore = 0;

        // Check WordPress version paths
        $this->checkPathPatterns($path, self::WP_VERSION_PATHS, $findings, $maxScore);

        // Check WordPress asset scanning
        $this->checkPathPatterns($path, self::WP_ASSET_SCANNING_PATHS, $findings, $maxScore);

        // Check Drupal version paths
        $this->checkPathPatterns($path, self::DRUPAL_VERSION_PATHS, $findings, $maxScore);

        // Check Joomla version paths
        $this->checkPathPatterns($path, self::JOOMLA_VERSION_PATHS, $findings, $maxScore);

        // Check version parameter probing
        $this->checkVersionParameter($uri, $findings, $maxScore);

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'Version fingerprinting detected: %s (path: %s)',
            implode('; ', array_slice(array_unique($findings), 0, 3)),
            substr($path, 0, 200)
        );

        return new DetectionResult([56, 57], $comment, $maxScore, $this->getName());
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

    private function checkVersionParameter(string $uri, array &$findings, int &$maxScore): void
    {
        // Detect ?v= or ?ver= or ?version= version probing in query string
        if (preg_match('/[?&](v|ver|version)=/i', $uri)) {
            // Only flag if the path looks like a CMS asset, not generic content
            $path = parse_url($uri, PHP_URL_PATH);
            if ($path === null || $path === false) {
                return;
            }

            $cmsAssetPattern = '#/(wp-content|wp-includes|wp-admin|sites|components|modules|libraries)/#i';
            if (preg_match($cmsAssetPattern, $path)) {
                $findings[] = 'Version parameter probing on CMS asset';
                $maxScore = max($maxScore, 50);
            }
        }
    }
}
