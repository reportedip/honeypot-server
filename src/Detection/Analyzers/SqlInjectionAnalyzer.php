<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;
use ReportedIp\Honeypot\Detection\PatternLibrary;

/**
 * Detects SQL injection attempts in URI, query parameters, POST data, and headers.
 *
 * Covers UNION-based, error-based, blind, time-based, and stacked query injection.
 */
final class SqlInjectionAnalyzer implements AnalyzerInterface
{
    public function getName(): string
    {
        return 'SqlInjection';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $findings = [];
        $maxScore = 0;

        // Check User-Agent for sqlmap signature
        $ua = $request->getUserAgent();
        if ($ua !== '' && preg_match('/sqlmap/i', $ua)) {
            $findings[] = 'sqlmap tool signature detected in User-Agent';
            $maxScore = max($maxScore, 95);
        }

        // Collect all inputs to scan
        $targets = $this->collectTargets($request);

        $patterns = PatternLibrary::sqlInjectionPatterns();

        foreach ($targets as $label => $value) {
            if ($value === '' || mb_strlen($value) < 3) {
                continue;
            }

            // Also check URL-decoded version
            $decoded = $this->deepDecode($value);

            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $value) || preg_match($pattern, $decoded)) {
                    $score = $this->scorePattern($pattern, $value);
                    $maxScore = max($maxScore, $score);
                    $findings[] = sprintf(
                        'SQL injection pattern in %s: matched %s',
                        $label,
                        $this->describePattern($pattern)
                    );
                    break; // One match per target is enough
                }
            }
        }

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'SQL injection attempt detected: %s',
            implode('; ', array_slice($findings, 0, 3))
        );

        return new DetectionResult([16, 45], $comment, $maxScore, $this->getName());
    }

    /**
     * Collect all request inputs as label => value pairs for scanning.
     *
     * @return array<string, string>
     */
    private function collectTargets(Request $request): array
    {
        $targets = [];

        $targets['URI'] = $request->getUri();
        $targets['path'] = $request->getPath();

        foreach ($request->getQueryParams() as $key => $val) {
            $targets["query param '{$key}'"] = is_string($val) ? $val : (string) $val;
        }

        foreach ($request->getPostData() as $key => $val) {
            $targets["POST field '{$key}'"] = is_string($val) ? $val : (string) $val;
        }

        // Check specific headers that may carry injection payloads
        $headerNames = ['Cookie', 'Referer', 'X-Forwarded-For', 'Authorization'];
        foreach ($headerNames as $name) {
            $headerVal = $request->getHeader($name);
            if ($headerVal !== null) {
                $targets["header '{$name}'"] = $headerVal;
            }
        }

        return $targets;
    }

    /**
     * Recursively URL-decode a value to catch double/triple encoding.
     */
    private function deepDecode(string $value, int $depth = 3): string
    {
        $decoded = $value;
        for ($i = 0; $i < $depth; $i++) {
            $next = urldecode($decoded);
            if ($next === $decoded) {
                break;
            }
            $decoded = $next;
        }
        return $decoded;
    }

    /**
     * Assign a confidence score based on the matched pattern severity.
     */
    private function scorePattern(string $pattern, string $value): int
    {
        // High confidence patterns
        if (preg_match('/union.*select|sleep|benchmark|waitfor|into\s+(out|dump)file/i', $pattern)) {
            return 90;
        }

        // Stacked queries
        if (preg_match('/drop|truncate|alter/i', $pattern)) {
            return 85;
        }

        // Medium confidence
        if (preg_match('/information_schema|load_file|group_concat/i', $pattern)) {
            return 80;
        }

        // Boolean-based (can have false positives)
        if (preg_match('/\bor\b.*?=|having|order\s+by/i', $pattern)) {
            return 70;
        }

        return 75;
    }

    /**
     * Create a human-readable description from a regex pattern.
     */
    private function describePattern(string $pattern): string
    {
        $map = [
            'union' => 'UNION-based injection',
            'sleep|benchmark|waitfor|pg_sleep' => 'time-based blind injection',
            'drop|insert|update|delete|truncate' => 'stacked query injection',
            'having|group.*by|order.*by' => 'error-based injection',
            'if\s*\(|case\s+when|substring|ascii|char' => 'blind injection',
            'information_schema' => 'schema enumeration',
            'load_file|into.*file' => 'file operation injection',
            '%27|%22|%3b|%25' => 'encoded injection',
            'concat|group_concat' => 'data extraction',
            '0x[0-9a-f]' => 'hex-encoded injection',
        ];

        foreach ($map as $keyword => $description) {
            if (preg_match('/' . $keyword . '/i', $pattern)) {
                return $description;
            }
        }

        return 'SQL injection pattern';
    }
}
