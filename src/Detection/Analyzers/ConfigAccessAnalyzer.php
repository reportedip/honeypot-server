<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;
use ReportedIp\Honeypot\Detection\PatternLibrary;

/**
 * Detects attempts to access configuration files.
 *
 * Checks for WordPress wp-config.php (and its backup variants), Drupal settings.php,
 * Joomla configuration.php, .env files, and other common configuration files.
 */
final class ConfigAccessAnalyzer implements AnalyzerInterface
{
    public function getName(): string
    {
        return 'ConfigAccess';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $path = strtolower($request->getPath());
        $uri = strtolower($request->getUri());

        if ($path === '' || $path === '/') {
            return null;
        }

        $findings = [];
        $maxScore = 0;

        $configPaths = PatternLibrary::configFilePaths();

        foreach ($configPaths as $configPath) {
            $needle = strtolower($configPath);

            // Check if the path ends with or contains the config file path
            if (str_contains($path, $needle) || str_contains($uri, $needle)) {
                $score = $this->scoreConfigPath($configPath);
                $maxScore = max($maxScore, $score);
                $findings[] = sprintf('Config file access attempt: %s', $configPath);
            }
        }

        // Additional regex-based checks for pattern variants
        $regexChecks = [
            // wp-config with various extensions
            '/wp-config\.php[\.\~]?/i' => ['WordPress configuration file', 90],
            '/wp-config\.(bak|old|save|orig|txt|tmp|copy|swp)/i' => ['WordPress config backup', 85],

            // Drupal settings
            '/sites\/default\/settings\.(php|local\.php)/i' => ['Drupal settings file', 85],

            // Joomla configuration
            '/configuration\.php(\.(bak|old|save|orig|txt))?/i' => ['Joomla configuration file', 80],

            // Environment files with various suffixes
            '/\.env(\.(local|production|staging|development|backup|old|save|example|sample|bak|dist))?$/i' => ['Environment configuration file', 85],

            // Database config files
            '/\b(db|database)\.(php|yml|yaml|json|ini)/i' => ['Database configuration file', 80],

            // Magento local.xml
            '/app\/etc\/(local\.xml|env\.php)/i' => ['Magento configuration file', 80],

            // Symfony parameters
            '/parameters\.(yml|yaml)/i' => ['Symfony parameters file', 75],

            // Generic sensitive config
            '/\bsecrets?\.(json|yml|yaml|php|xml)/i' => ['Secrets configuration file', 85],
            '/\bcredentials?\.(json|yml|yaml|php|xml)/i' => ['Credentials file', 85],
            '/config\.(inc\.php|php)/i' => ['PHP configuration file', 70],
        ];

        foreach ($regexChecks as $pattern => [$description, $score]) {
            if (preg_match($pattern, $path)) {
                if (!$this->isDuplicate($findings, $description)) {
                    $findings[] = $description;
                    $maxScore = max($maxScore, $score);
                }
            }
        }

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'Configuration file access attempt: %s (path: %s)',
            implode('; ', array_slice(array_unique($findings), 0, 3)),
            substr($request->getPath(), 0, 200)
        );

        return new DetectionResult([58, 15], $comment, $maxScore, $this->getName());
    }

    private function scoreConfigPath(string $path): int
    {
        $lowerPath = strtolower($path);

        // WordPress config and variants
        if (str_contains($lowerPath, 'wp-config')) {
            return 90;
        }

        // Environment files
        if (str_starts_with($lowerPath, '.env')) {
            return 85;
        }

        // Secrets/credentials
        if (str_contains($lowerPath, 'secret') || str_contains($lowerPath, 'credential')) {
            return 85;
        }

        // CMS-specific configs
        if (str_contains($lowerPath, 'settings.php') || str_contains($lowerPath, 'configuration.php')) {
            return 85;
        }

        // Database configs
        if (str_contains($lowerPath, 'database') || str_contains($lowerPath, 'db.php')) {
            return 80;
        }

        // Generic config files
        return 70;
    }

    private function isDuplicate(array $findings, string $description): bool
    {
        foreach ($findings as $finding) {
            if (stripos($finding, $description) !== false) {
                return true;
            }
        }
        return false;
    }
}
