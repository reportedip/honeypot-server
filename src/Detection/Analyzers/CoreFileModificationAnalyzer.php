<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;

/**
 * Detects attempts to modify CMS core files via built-in editors and update mechanisms.
 *
 * Checks for POST to plugin/theme editors (code injection), direct access to core PHP files,
 * plugin/theme installation via update.php, direct access to wp-admin includes,
 * Drupal module installation, and Joomla extension installation endpoints.
 */
final class CoreFileModificationAnalyzer implements AnalyzerInterface
{
    /** WordPress core files that should not be accessed directly. */
    private const WP_CORE_FILES = [
        '/wp-load.php',
        '/wp-settings.php',
        '/wp-blog-header.php',
        '/wp-config-sample.php',
        '/wp-cron.php',
        '/wp-links-opml.php',
        '/wp-mail.php',
        '/wp-activate.php',
    ];

    public function getName(): string
    {
        return 'CoreFileModification';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $path = $request->getPath();
        $pathLower = strtolower($path);

        if ($pathLower === '' || $pathLower === '/') {
            return null;
        }

        $findings = [];
        $maxScore = 0;

        // === WordPress Checks ===

        // POST to plugin-editor.php or theme-editor.php (code injection via built-in editor)
        if ($request->isPost()) {
            if (preg_match('/\/wp-admin\/plugin-editor\.php/i', $pathLower)) {
                $findings[] = 'POST to plugin editor (code injection attempt)';
                $maxScore = max($maxScore, 80);
            }

            if (preg_match('/\/wp-admin\/theme-editor\.php/i', $pathLower)) {
                $findings[] = 'POST to theme editor (code injection attempt)';
                $maxScore = max($maxScore, 80);
            }

            // POST to update.php (plugin/theme installation)
            if (preg_match('/\/wp-admin\/update\.php/i', $pathLower)) {
                $findings[] = 'POST to update.php (plugin/theme installation attempt)';
                $maxScore = max($maxScore, 75);
            }

            // POST to update-core.php
            if (preg_match('/\/wp-admin\/update-core\.php/i', $pathLower)) {
                $findings[] = 'POST to update-core.php (core update attempt)';
                $maxScore = max($maxScore, 75);
            }
        }

        // GET to plugin/theme editor (probing)
        if ($request->isGet()) {
            if (preg_match('/\/wp-admin\/plugin-editor\.php/i', $pathLower)) {
                $findings[] = 'Plugin editor access probe';
                $maxScore = max($maxScore, 60);
            }

            if (preg_match('/\/wp-admin\/theme-editor\.php/i', $pathLower)) {
                $findings[] = 'Theme editor access probe';
                $maxScore = max($maxScore, 60);
            }
        }

        // Direct access to WordPress core files
        foreach (self::WP_CORE_FILES as $coreFile) {
            if (str_ends_with($pathLower, strtolower($coreFile))) {
                $findings[] = sprintf('Direct access to core file: %s', $coreFile);
                $maxScore = max($maxScore, 65);
                break;
            }
        }

        // Access to /wp-admin/includes/ PHP files directly
        if (preg_match('/\/wp-admin\/includes\/[^\/]+\.php/i', $pathLower)) {
            $findings[] = 'Direct access to wp-admin/includes/ PHP file';
            $maxScore = max($maxScore, 70);
        }

        // Access to /wp-includes/ PHP files with suspicious patterns
        if (preg_match('/\/wp-includes\/[^\/]+\.php/i', $pathLower)) {
            // Exclude common legitimate includes
            if (!preg_match('/\/(wp-includes\/(js|css|images|fonts))\//i', $pathLower)) {
                $findings[] = 'Direct access to wp-includes/ PHP file';
                $maxScore = max($maxScore, 55);
            }
        }

        // === Drupal Checks ===

        if ($request->isPost()) {
            // Drupal: POST to admin module install
            if (preg_match('/\/admin\/modules\/install/i', $pathLower)) {
                $findings[] = 'Drupal module installation attempt';
                $maxScore = max($maxScore, 75);
            }

            // Drupal: POST to update.php
            if (preg_match('/\/update\.php$/i', $pathLower)) {
                $findings[] = 'Drupal update.php POST (core update attempt)';
                $maxScore = max($maxScore, 70);
            }

            // Drupal: POST to admin/appearance/install
            if (preg_match('/\/admin\/appearance\/install/i', $pathLower)) {
                $findings[] = 'Drupal theme installation attempt';
                $maxScore = max($maxScore, 70);
            }
        }

        // Drupal: GET to update.php
        if ($request->isGet() && preg_match('/\/update\.php$/i', $pathLower)) {
            $findings[] = 'Drupal update.php access probe';
            $maxScore = max($maxScore, 55);
        }

        // === Joomla Checks ===

        if ($request->isPost()) {
            // Joomla: POST to administrator with com_installer
            $uri = strtolower($request->getUri());
            if (preg_match('/\/administrator\/index\.php/i', $pathLower)) {
                $postData = $request->getPostData();
                $option = $postData['option'] ?? '';
                $queryOption = $request->getQueryParam('option') ?? '';

                if (strtolower((string) $option) === 'com_installer' || strtolower((string) $queryOption) === 'com_installer') {
                    $findings[] = 'Joomla extension installation attempt (com_installer)';
                    $maxScore = max($maxScore, 75);
                }

                // Also check in URI for query param
                if (str_contains($uri, 'option=com_installer')) {
                    $findings[] = 'Joomla com_installer access via URI';
                    $maxScore = max($maxScore, 75);
                }
            }
        }

        // Joomla: Direct access to administrator includes
        if (preg_match('/\/administrator\/includes\/[^\/]+\.php/i', $pathLower)) {
            $findings[] = 'Direct access to Joomla administrator includes';
            $maxScore = max($maxScore, 65);
        }

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'Core file modification attempt: %s (path: %s)',
            implode('; ', array_slice(array_unique($findings), 0, 3)),
            substr($request->getPath(), 0, 200)
        );

        return new DetectionResult([37, 46], $comment, $maxScore, $this->getName());
    }
}
