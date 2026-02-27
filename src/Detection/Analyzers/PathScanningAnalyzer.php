<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;
use ReportedIp\Honeypot\Detection\PatternLibrary;

/**
 * Detects path scanning and probing for sensitive files.
 *
 * Identifies requests for backup files, source control directories,
 * configuration files, log files, database dumps, admin panels,
 * and common scanner targets.
 */
final class PathScanningAnalyzer implements AnalyzerInterface
{
    public function getName(): string
    {
        return 'PathScanning';
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

        // Check for backup file extensions
        $backupPatterns = [
            '/\.(bak|old|orig|save|swp|copy|tmp|temp)$/i' => ['Backup file probe', 55],
            '/~$/i' => ['Editor backup file probe', 50],
            '/\.(sql|sqlite|db)$/i' => ['Database file probe', 65],
            '/\.(log|logs)$/i' => ['Log file probe', 50],
            '/\.(tar|tar\.gz|tgz|zip|rar|7z|gz|bz2)$/i' => ['Archive file probe', 55],
        ];

        foreach ($backupPatterns as $pattern => [$description, $score]) {
            if (preg_match($pattern, $path)) {
                $findings[] = $description;
                $maxScore = max($maxScore, $score);
                break;
            }
        }

        // Check against the sensitive file paths library
        $sensitivePatterns = PatternLibrary::sensitiveFilePaths();
        foreach ($sensitivePatterns as $pattern) {
            if (preg_match($pattern, $path)) {
                $findings[] = sprintf('Sensitive file access: %s', $this->describeSensitivePath($pattern));
                $maxScore = max($maxScore, $this->scoreSensitivePath($pattern));
                break;
            }
        }

        // Check for common scanner / admin panel paths
        $scannerPaths = [
            '/\/(admin|administrator|manager|panel|console|dashboard|backend)\/?$/i' => ['Admin panel probe', 45],
            '/\/(login|signin|auth|authenticate)\/?$/i' => ['Authentication endpoint probe', 40],
            '/\/(phpmyadmin|pma|myadmin|mysqladmin|dbadmin|adminer)\/?/i' => ['Database admin panel probe', 65],
            '/\/(cgi-bin|cgi)\//i' => ['CGI directory probe', 50],
            '/\/(wp-admin|wp-includes)\/?/i' => ['WordPress admin probe', 45],
            '/\/(xmlrpc\.php|wp-cron\.php)$/i' => ['WordPress system file probe', 50],
            '/\/server-(status|info)$/i' => ['Server status page probe', 55],
            '/\/(\.well-known|crossdomain\.xml|clientaccesspolicy\.xml)/i' => ['Policy file probe', 40],
            '/\/(robots\.txt|sitemap\.xml)$/i' => ['Reconnaissance (robots/sitemap)', 40],
            '/\/(actuator|health|metrics|prometheus)\/?/i' => ['Application monitoring endpoint probe', 55],
            '/\/(api|v1|v2|v3)\/(admin|debug|test)\//i' => ['API admin/debug endpoint probe', 55],
        ];

        foreach ($scannerPaths as $pattern => [$description, $score]) {
            if (preg_match($pattern, $path)) {
                $findings[] = $description;
                $maxScore = max($maxScore, $score);
                break;
            }
        }

        // Check for source control directory access
        if (preg_match('/\/\.(git|svn|hg|bzr)(\/|$)/i', $path)) {
            $findings[] = 'Source control directory probe';
            $maxScore = max($maxScore, 70);
        }

        // Check for IDE/editor directories
        if (preg_match('/\/\.(idea|vscode|project|settings)(\/|$)/i', $path)) {
            $findings[] = 'IDE/editor configuration probe';
            $maxScore = max($maxScore, 50);
        }

        // Check for phpinfo/test files
        if (preg_match('/\/(phpinfo|info|test|pi|i)\.php$/i', $path)) {
            $findings[] = 'PHP info/test file probe';
            $maxScore = max($maxScore, 60);
        }

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'Path scanning/probing detected: %s (path: %s)',
            implode('; ', array_slice($findings, 0, 3)),
            substr($path, 0, 200)
        );

        return new DetectionResult([14, 15], $comment, $maxScore, $this->getName());
    }

    private function describeSensitivePath(string $pattern): string
    {
        $map = [
            '\.env' => 'environment file',
            '\.git' => 'Git repository',
            '\.svn' => 'SVN repository',
            '\.htaccess|\.htpasswd' => 'Apache configuration',
            'composer|package|Gemfile|requirements|Pipfile' => 'dependency manifest',
            'error.*log|access.*log|debug.*log|\.log' => 'log file',
            '\.sql|\.sqlite|\.db|dump' => 'database file',
            'phpinfo|info\.php|test\.php' => 'PHP info/test file',
            'phpmyadmin|adminer' => 'database admin panel',
            'web\.config' => 'IIS configuration',
            'DS_Store|Thumbs|desktop\.ini' => 'OS metadata file',
            '\.idea|\.vscode|\.project' => 'IDE configuration',
        ];

        foreach ($map as $keyword => $description) {
            if (preg_match('/' . $keyword . '/i', $pattern)) {
                return $description;
            }
        }

        return 'sensitive file';
    }

    private function scoreSensitivePath(string $pattern): int
    {
        if (preg_match('/\.env|\.htpasswd|\.git/i', $pattern)) {
            return 70;
        }

        if (preg_match('/phpmyadmin|adminer|phpinfo/i', $pattern)) {
            return 65;
        }

        if (preg_match('/\.sql|\.db|dump/i', $pattern)) {
            return 65;
        }

        if (preg_match('/error.*log|access.*log/i', $pattern)) {
            return 55;
        }

        if (preg_match('/composer|package|requirements/i', $pattern)) {
            return 50;
        }

        return 50;
    }
}
