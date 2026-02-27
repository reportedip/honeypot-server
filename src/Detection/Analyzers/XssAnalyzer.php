<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;
use ReportedIp\Honeypot\Detection\PatternLibrary;

/**
 * Detects Cross-Site Scripting (XSS) attempts in URI, query parameters,
 * and POST data.
 *
 * Covers reflected, stored, and DOM-based XSS vectors including script tags,
 * event handlers, protocol handlers, and encoded variants.
 */
final class XssAnalyzer implements AnalyzerInterface
{
    public function getName(): string
    {
        return 'XSS';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $findings = [];
        $maxScore = 0;

        $targets = $this->collectTargets($request);
        $patterns = PatternLibrary::xssPatterns();

        foreach ($targets as $label => $value) {
            if ($value === '' || mb_strlen($value) < 4) {
                continue;
            }

            $decoded = $this->deepDecode($value);

            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $value) || preg_match($pattern, $decoded)) {
                    $score = $this->scorePattern($pattern);
                    $maxScore = max($maxScore, $score);
                    $findings[] = sprintf(
                        'XSS pattern in %s: %s',
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
            'Cross-site scripting (XSS) attempt detected: %s',
            implode('; ', array_slice($findings, 0, 3))
        );

        return new DetectionResult([44, 45], $comment, $maxScore, $this->getName());
    }

    /**
     * @return array<string, string>
     */
    private function collectTargets(Request $request): array
    {
        $targets = [];

        $targets['URI'] = $request->getUri();

        foreach ($request->getQueryParams() as $key => $val) {
            $targets["query param '{$key}'"] = is_string($val) ? $val : (string) $val;
        }

        foreach ($request->getPostData() as $key => $val) {
            $targets["POST field '{$key}'"] = is_string($val) ? $val : (string) $val;
        }

        $referer = $request->getHeader('Referer');
        if ($referer !== null) {
            $targets['Referer header'] = $referer;
        }

        return $targets;
    }

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

    private function scorePattern(string $pattern): int
    {
        // Script tags are very high confidence
        if (preg_match('/script/i', $pattern)) {
            return 90;
        }

        // Event handlers with payload
        if (preg_match('/on\w+.*?(alert|eval|function|javascript)/i', $pattern)) {
            return 85;
        }

        // Javascript protocol
        if (preg_match('/javascript\s*:/i', $pattern)) {
            return 85;
        }

        // SVG/IMG with event handlers
        if (preg_match('/svg|img/i', $pattern)) {
            return 80;
        }

        // Iframe injection
        if (preg_match('/iframe/i', $pattern)) {
            return 80;
        }

        // Eval/Function
        if (preg_match('/eval|Function/i', $pattern)) {
            return 75;
        }

        // Template injection (could be false positive)
        if (preg_match('/\{|\\$/i', $pattern)) {
            return 60;
        }

        // Individual event handlers
        if (preg_match('/on(error|load|click|focus|mouse)/i', $pattern)) {
            return 70;
        }

        return 65;
    }

    private function describePattern(string $pattern): string
    {
        $map = [
            'script' => 'script tag injection',
            'onerror|onload|onclick|onfocus|onmouse|onchange|onsubmit|onkey' => 'event handler injection',
            'javascript\s*:' => 'javascript protocol handler',
            'data\s*:' => 'data URI injection',
            'svg' => 'SVG-based XSS',
            'img' => 'IMG-based XSS',
            'iframe' => 'iframe injection',
            'expression|eval|Function|setTimeout|setInterval' => 'code execution attempt',
            '\{\{|\$\{' => 'template injection',
            'object|embed|applet' => 'embedded object injection',
            '&#|%3[cC]' => 'encoded XSS payload',
            'document\.|window\.' => 'DOM manipulation attempt',
            'XMLHttpRequest|fetch' => 'data exfiltration attempt',
        ];

        foreach ($map as $keyword => $description) {
            if (preg_match('/' . $keyword . '/i', $pattern)) {
                return $description;
            }
        }

        return 'XSS pattern';
    }
}
