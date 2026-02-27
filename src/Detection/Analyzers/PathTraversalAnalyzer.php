<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;
use ReportedIp\Honeypot\Detection\PatternLibrary;

/**
 * Detects path/directory traversal attempts in URI and query parameters.
 *
 * Covers standard traversal sequences, encoded variants, null byte injection,
 * and PHP stream wrapper abuse.
 */
final class PathTraversalAnalyzer implements AnalyzerInterface
{
    public function getName(): string
    {
        return 'PathTraversal';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $findings = [];
        $maxScore = 0;

        $targets = [];
        $targets['URI'] = $request->getUri();
        $targets['path'] = $request->getPath();

        foreach ($request->getQueryParams() as $key => $val) {
            $targets["query param '{$key}'"] = is_string($val) ? $val : (string) $val;
        }

        foreach ($request->getPostData() as $key => $val) {
            $targets["POST field '{$key}'"] = is_string($val) ? $val : (string) $val;
        }

        $patterns = PatternLibrary::pathTraversalPatterns();

        foreach ($targets as $label => $value) {
            if ($value === '' || mb_strlen($value) < 3) {
                continue;
            }

            $decoded = $this->deepDecode($value);

            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $value) || preg_match($pattern, $decoded)) {
                    $score = $this->scorePattern($pattern);
                    $maxScore = max($maxScore, $score);
                    $findings[] = sprintf(
                        'Path traversal in %s: %s',
                        $label,
                        $this->describePattern($pattern)
                    );
                    break;
                }
            }
        }

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'Path traversal attempt detected: %s',
            implode('; ', array_slice($findings, 0, 3))
        );

        return new DetectionResult([21], $comment, $maxScore, $this->getName());
    }

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

    private function scorePattern(string $pattern): int
    {
        // Accessing system files
        if (preg_match('/etc\/passwd|etc\/shadow|proc\/self|windows.*system32|boot\.ini/i', $pattern)) {
            return 95;
        }

        // PHP stream wrappers
        if (preg_match('/php:\/\/|expect:\/\/|phar:\/\/|zip:\/\//i', $pattern)) {
            return 90;
        }

        // Null byte injection
        if (preg_match('/%00/i', $pattern)) {
            return 85;
        }

        // Double-encoded traversal
        if (preg_match('/%25/i', $pattern)) {
            return 85;
        }

        // Standard traversal
        if (preg_match('/\.\.\//i', $pattern)) {
            return 75;
        }

        // Encoded traversal
        if (preg_match('/%2e|%2f|%5c/i', $pattern)) {
            return 80;
        }

        return 75;
    }

    private function describePattern(string $pattern): string
    {
        $map = [
            'etc\/passwd|etc\/shadow' => 'system password file access',
            'proc\/self' => 'process environment access',
            'windows|winnt|boot\.ini' => 'Windows system file access',
            'php:\/\/filter' => 'PHP filter wrapper abuse',
            'php:\/\/input' => 'PHP input wrapper abuse',
            'expect:\/\/' => 'expect wrapper RCE',
            'phar:\/\/' => 'phar deserialization attack',
            'zip:\/\/' => 'zip wrapper abuse',
            '%00' => 'null byte injection',
            '%252e|%255c' => 'double-encoded traversal',
            '%2e|%2f|%5c' => 'URL-encoded traversal',
            '\.\.\/' => 'directory traversal sequence',
            '\.\.\\\\\\\\' => 'Windows directory traversal',
            'data:\/\/' => 'data wrapper abuse',
        ];

        foreach ($map as $keyword => $description) {
            if (preg_match('#' . $keyword . '#i', $pattern)) {
                return $description;
            }
        }

        return 'path traversal pattern';
    }
}
