<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;

/**
 * Detects open redirect attack attempts.
 *
 * Checks for query parameters commonly used for redirects that contain
 * external URLs, JavaScript protocol handlers, data URIs, and encoded
 * redirect payloads. Covers WordPress, Drupal, and Joomla redirect patterns.
 */
final class OpenRedirectAnalyzer implements AnalyzerInterface
{
    /** Query parameter names commonly used for redirects. */
    private const REDIRECT_PARAMS = [
        'redirect',
        'redirect_to',
        'return',
        'returnto',
        'next',
        'url',
        'goto',
        'destination',
        'continue',
        'rurl',
        'return_url',
        'redirect_url',
        'forward',
        'forward_to',
        'target',
        'to',
        'out',
        'view',
        'ref',
        'redir',
    ];

    /** CMS-specific redirect paths. */
    private const CMS_REDIRECT_PATHS = [
        '/\/wp-login\.php/i',   // WordPress login redirect_to
        '/\/user\/login/i',     // Drupal user login
        '/\/user\/logout/i',    // Drupal user logout
    ];

    public function getName(): string
    {
        return 'OpenRedirect';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $findings = [];
        $maxScore = 0;

        $queryParams = $request->getQueryParams();
        $postData = $request->getPostData();
        $path = $request->getPath();

        // Combine query and POST params for analysis
        $allParams = [];
        foreach ($queryParams as $key => $val) {
            $allParams[$key] = is_string($val) ? $val : (string) $val;
        }
        foreach ($postData as $key => $val) {
            $allParams[$key] = is_string($val) ? $val : (string) $val;
        }

        foreach ($allParams as $paramName => $paramValue) {
            if ($paramValue === '') {
                continue;
            }

            $paramNameLower = strtolower($paramName);
            $isRedirectParam = in_array($paramNameLower, self::REDIRECT_PARAMS, true);

            if (!$isRedirectParam) {
                continue;
            }

            $decoded = $this->deepDecode($paramValue);

            // Check for external URLs (http:// or https:// pointing to a different domain)
            if ($this->containsExternalUrl($decoded, $request)) {
                $findings[] = sprintf(
                    'External URL in redirect param "%s": %s',
                    $paramName,
                    substr($decoded, 0, 100)
                );
                $maxScore = max($maxScore, 70);
            }

            // Check for JavaScript protocol
            if (preg_match('/^\s*javascript\s*:/i', $decoded)) {
                $findings[] = sprintf('JavaScript protocol in redirect param "%s"', $paramName);
                $maxScore = max($maxScore, 80);
            }

            // Check for data: protocol
            if (preg_match('/^\s*data\s*:/i', $decoded)) {
                $findings[] = sprintf('Data URI in redirect param "%s"', $paramName);
                $maxScore = max($maxScore, 75);
            }

            // Check for encoded redirect URLs: %68%74%74%70 = "http"
            if (preg_match('/%68%74%74%70/i', $paramValue)) {
                $findings[] = sprintf('URL-encoded HTTP protocol in redirect param "%s"', $paramName);
                $maxScore = max($maxScore, 70);
            }

            // Check for double-encoded patterns
            if (preg_match('/%25[0-9a-fA-F]{2}%25[0-9a-fA-F]{2}/i', $paramValue)) {
                $findings[] = sprintf('Double-encoded redirect in param "%s"', $paramName);
                $maxScore = max($maxScore, 75);
            }

            // Protocol-relative URL (//evil.com)
            if (preg_match('#^\s*//[^/]#', $decoded)) {
                $findings[] = sprintf('Protocol-relative URL in redirect param "%s"', $paramName);
                $maxScore = max($maxScore, 65);
            }
        }

        // WordPress-specific: /wp-login.php?redirect_to=http://evil.com
        if (preg_match('/\/wp-login\.php/i', $path)) {
            $redirectTo = $queryParams['redirect_to'] ?? ($postData['redirect_to'] ?? null);
            if ($redirectTo !== null && is_string($redirectTo) && $redirectTo !== '') {
                $decodedRedirect = $this->deepDecode($redirectTo);
                if ($this->containsExternalUrl($decodedRedirect, $request)) {
                    $findings[] = sprintf(
                        'WordPress login redirect to external URL: %s',
                        substr($decodedRedirect, 0, 100)
                    );
                    $maxScore = max($maxScore, 75);
                }
            }
        }

        // Drupal-specific: ?destination=http://evil.com
        $destination = $queryParams['destination'] ?? ($postData['destination'] ?? null);
        if ($destination !== null && is_string($destination) && $destination !== '') {
            $decodedDest = $this->deepDecode($destination);
            if ($this->containsExternalUrl($decodedDest, $request) ||
                preg_match('/^\s*javascript\s*:/i', $decodedDest) ||
                preg_match('/^\s*data\s*:/i', $decodedDest)) {
                $findings[] = sprintf(
                    'Drupal destination redirect abuse: %s',
                    substr($decodedDest, 0, 100)
                );
                $maxScore = max($maxScore, 70);
            }
        }

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'Open redirect attempt detected: %s',
            implode('; ', array_slice($findings, 0, 3))
        );

        return new DetectionResult([50, 7, 21], $comment, $maxScore, $this->getName());
    }

    /**
     * Check if a value contains an external URL (not relative or same-origin).
     */
    private function containsExternalUrl(string $value, Request $request): bool
    {
        // Match http:// or https:// URLs
        if (!preg_match('#https?://#i', $value)) {
            return false;
        }

        // Extract the hostname from the redirect target
        $parsed = parse_url($value);
        if ($parsed === false || !isset($parsed['host'])) {
            return false;
        }

        // Compare with current Host header
        $hostHeader = $request->getHeader('Host');
        if ($hostHeader === null || $hostHeader === '') {
            // No Host header means any external URL is suspicious
            return true;
        }

        // Strip port from Host header for comparison
        $currentHost = strtolower(explode(':', $hostHeader)[0]);
        $targetHost = strtolower($parsed['host']);

        return $currentHost !== $targetHost;
    }

    /**
     * Decode URL-encoded and HTML-entity-encoded values iteratively.
     */
    private function deepDecode(string $value, int $depth = 3): string
    {
        $decoded = $value;
        for ($i = 0; $i < $depth; $i++) {
            $next = rawurldecode(html_entity_decode($decoded, ENT_QUOTES | ENT_HTML5, 'UTF-8'));
            if ($next === $decoded) {
                break;
            }
            $decoded = $next;
        }
        return $decoded;
    }
}
