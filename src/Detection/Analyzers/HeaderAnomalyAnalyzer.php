<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;

/**
 * Detects anomalies in HTTP request headers.
 *
 * Checks for missing Host, CRLF injection, abnormally large headers,
 * spoofed X-Forwarded-For, and other header manipulation techniques.
 */
final class HeaderAnomalyAnalyzer implements AnalyzerInterface
{
    private const MAX_HEADER_SIZE = 8192; // 8KB

    public function getName(): string
    {
        return 'HeaderAnomaly';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $findings = [];
        $maxScore = 0;
        $headers = $request->getHeaders();

        // Check for missing or empty Host header
        $host = $request->getHeader('Host');
        if ($host === null || $host === '') {
            $findings[] = 'Missing or empty Host header';
            $maxScore = max($maxScore, 50);
        }

        // Check for CRLF injection in headers
        foreach ($headers as $name => $value) {
            $headerValue = is_array($value) ? implode(', ', $value) : (string) $value;

            if (preg_match('/%0[dD]%0[aA]|\r\n|\\\\r\\\\n/', $headerValue)) {
                $findings[] = sprintf('CRLF injection in header "%s"', $name);
                $maxScore = max($maxScore, 70);
            }

            // Check for abnormally large headers
            if (mb_strlen($headerValue) > self::MAX_HEADER_SIZE) {
                $findings[] = sprintf(
                    'Abnormally large header "%s" (%d bytes)',
                    $name,
                    mb_strlen($headerValue)
                );
                $maxScore = max($maxScore, 50);
            }
        }

        // Check for X-Forwarded-For manipulation
        $xff = $request->getHeader('X-Forwarded-For');
        if ($xff !== null) {
            if ($this->containsLoopbackEntry($xff)) {
                $findings[] = 'Suspicious X-Forwarded-For with loopback address';
                $maxScore = max($maxScore, 45);
            }
            // Multiple X-Forwarded-For entries suggesting header injection
            if (substr_count($xff, ',') > 5) {
                $findings[] = 'Excessive X-Forwarded-For chain (possible header injection)';
                $maxScore = max($maxScore, 40);
            }
        }

        // Check for suspicious Referer with attack payloads
        $referer = $request->getHeader('Referer');
        if ($referer !== null && $referer !== '') {
            if (preg_match('/<script|javascript:|onerror=|union\s+select|\.\.\/|%3[cC]script/i', $referer)) {
                $findings[] = 'Attack payload detected in Referer header';
                $maxScore = max($maxScore, 65);
            }
        }

        // Check for Connection header manipulation
        $connection = $request->getHeader('Connection');
        if ($connection !== null && preg_match('/keep-alive.*?,.*?keep-alive/i', $connection)) {
            $findings[] = 'Connection header manipulation detected';
            $maxScore = max($maxScore, 35);
        }

        // Check for suspicious Accept headers (not typical browser patterns)
        $accept = $request->getHeader('Accept');
        if ($accept !== null) {
            if (preg_match('/\.\.\//i', $accept) || preg_match('/<script/i', $accept)) {
                $findings[] = 'Attack payload in Accept header';
                $maxScore = max($maxScore, 60);
            }
        }

        // Check for method override headers (potential bypass)
        $methodOverride = $request->getHeader('X-HTTP-Method-Override')
            ?? $request->getHeader('X-Method-Override');
        if ($methodOverride !== null) {
            $findings[] = sprintf('HTTP method override header present: %s', $methodOverride);
            $maxScore = max($maxScore, 40);
        }

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'HTTP header anomaly detected: %s',
            implode('; ', array_slice($findings, 0, 3))
        );

        return new DetectionResult([15, 21], $comment, $maxScore, $this->getName());
    }

    /**
     * Check if an X-Forwarded-For chain contains a loopback/unspecified entry.
     *
     * Vergleicht jeden Eintrag exakt, damit IPv6-Adressen wie
     * 2a06:98c0:3600::103 (enthalten "::1" als Substring) nicht
     * fälschlich als Loopback erkannt werden.
     */
    private function containsLoopbackEntry(string $xff): bool
    {
        $suspicious = ['localhost', '::1', '0.0.0.0', '::'];

        foreach (explode(',', $xff) as $entry) {
            $entry = strtolower(trim($entry));
            // Optionalen Port abschneiden (z. B. "127.0.0.1:8080")
            $entry = preg_replace('/^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/', '$1', $entry) ?? $entry;

            if (in_array($entry, $suspicious, true) || str_starts_with($entry, '127.')) {
                return true;
            }
        }

        return false;
    }
}
