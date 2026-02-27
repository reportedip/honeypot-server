<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;

/**
 * Detects WordPress cron abuse and API endpoint abuse.
 *
 * Covers direct wp-cron.php access (especially with suspicious user agents),
 * POST to wp-cron.php with body content, non-browser access to heartbeat,
 * and bulk REST API operations using write methods.
 */
final class WpCronAbuseAnalyzer implements AnalyzerInterface
{
    /** User-Agent substrings typical of real browsers. */
    private const BROWSER_UA_PATTERNS = [
        '/Mozilla\/\d/i',
        '/Chrome\/\d/i',
        '/Firefox\/\d/i',
        '/Safari\/\d/i',
        '/Edge\/\d/i',
        '/Opera\/\d/i',
    ];

    public function getName(): string
    {
        return 'WpCronAbuse';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $findings = [];
        $maxScore = 0;

        // Check for wp-cron.php abuse
        $this->checkWpCron($request, $findings, $maxScore);

        // Check for heartbeat abuse by non-browser UAs
        $this->checkHeartbeatAbuse($request, $findings, $maxScore);

        // Check for REST API bulk operations
        $this->checkRestApiBulkOperations($request, $findings, $maxScore);

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'WP cron/API abuse detected: %s (path: %s)',
            implode('; ', array_slice(array_unique($findings), 0, 3)),
            substr($request->getPath(), 0, 200)
        );

        return new DetectionResult([54, 4], $comment, $maxScore, $this->getName());
    }

    private function checkWpCron(Request $request, array &$findings, int &$maxScore): void
    {
        $path = $request->getPath();

        if (!preg_match('#/wp-cron\.php#i', $path)) {
            return;
        }

        $userAgent = $request->getUserAgent();
        $isBrowser = $this->isBrowserUserAgent($userAgent);

        if ($request->isPost()) {
            $body = $request->getBody();
            if ($body !== '') {
                $findings[] = 'POST to wp-cron.php with body content';
                $maxScore = max($maxScore, 65);
            } else {
                $findings[] = 'POST to wp-cron.php';
                $maxScore = max($maxScore, 50);
            }
        } else {
            // GET access to wp-cron.php
            if (!$isBrowser) {
                $findings[] = sprintf(
                    'Direct wp-cron.php access with non-browser UA: %s',
                    substr($userAgent, 0, 80)
                );
                $maxScore = max($maxScore, 55);
            } else {
                $findings[] = 'Direct wp-cron.php access';
                $maxScore = max($maxScore, 40);
            }
        }
    }

    private function checkHeartbeatAbuse(Request $request, array &$findings, int &$maxScore): void
    {
        $uri = $request->getUri();

        if (!preg_match('#/wp-admin/admin-ajax\.php.*action=heartbeat#i', $uri)
            && !preg_match('#/wp-admin/admin-ajax\.php#i', $request->getPath())
        ) {
            return;
        }

        // Only flag admin-ajax heartbeat specifically
        $action = $request->getQueryParam('action');
        $postAction = $request->getPostData()['action'] ?? null;
        $effectiveAction = $action ?? (is_string($postAction) ? $postAction : null);

        if ($effectiveAction !== 'heartbeat') {
            return;
        }

        $userAgent = $request->getUserAgent();
        if (!$this->isBrowserUserAgent($userAgent)) {
            $findings[] = sprintf(
                'Heartbeat endpoint accessed by non-browser UA: %s',
                substr($userAgent, 0, 80)
            );
            $maxScore = max($maxScore, 55);
        }
    }

    private function checkRestApiBulkOperations(Request $request, array &$findings, int &$maxScore): void
    {
        $path = $request->getPath();
        $method = $request->getMethod();

        if (!preg_match('#/wp-json/wp/v2/#i', $path)) {
            return;
        }

        // Flag POST, DELETE, PUT methods to REST API as bulk operation attempts
        $writeMethods = ['POST', 'DELETE', 'PUT', 'PATCH'];
        if (in_array($method, $writeMethods, true)) {
            $findings[] = sprintf('REST API write operation (%s %s)', $method, substr($path, 0, 100));
            $maxScore = max($maxScore, 60);
        }
    }

    private function isBrowserUserAgent(string $userAgent): bool
    {
        if ($userAgent === '') {
            return false;
        }

        foreach (self::BROWSER_UA_PATTERNS as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                return true;
            }
        }

        return false;
    }
}
