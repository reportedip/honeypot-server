<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;

/**
 * Detects resource exhaustion and denial-of-service attack patterns.
 *
 * Covers oversized request bodies, POST to resource-heavy endpoints,
 * excessively long query strings, regex DoS patterns in parameters,
 * XML entity expansion (XXE/billion laughs), and excessive query parameter counts.
 */
final class ResourceExhaustionAnalyzer implements AnalyzerInterface
{
    /** Maximum acceptable Content-Length in bytes (100 KB). */
    private const MAX_CONTENT_LENGTH = 102400;

    /** Maximum acceptable query string length in characters. */
    private const MAX_QUERY_STRING_LENGTH = 2048;

    /** Maximum acceptable number of query parameters. */
    private const MAX_QUERY_PARAMS = 50;

    /** Resource-heavy endpoint patterns. */
    private const HEAVY_ENDPOINTS = [
        '#/wp-admin/admin-ajax\.php\?action=heartbeat#i',
        '#/wp-admin/admin-ajax\.php.*action=heartbeat#i',
    ];

    /** Regex DoS patterns (nested quantifiers). */
    private const REDOS_PATTERNS = [
        '/\(([^()]*\+)+\)\+/',
        '/\(\(([^()]*\+)+\)\+\)\+/',
        '/\([^()]*\*\)\*/',
        '/\([^()]*\+\)\{/',
    ];

    /** XML entity expansion indicators. */
    private const XXE_PATTERNS = [
        '/<!ENTITY/i',
        '/<!DOCTYPE[^>]*\[/i',
        '/SYSTEM\s+["\']file:/i',
        '/SYSTEM\s+["\']https?:/i',
        '/SYSTEM\s+["\']php:/i',
        '/SYSTEM\s+["\']expect:/i',
    ];

    public function getName(): string
    {
        return 'ResourceExhaustion';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $findings = [];
        $maxScore = 0;

        // Check for oversized request body via Content-Length header
        $this->checkContentLength($request, $findings, $maxScore);

        // Check for POST to resource-heavy endpoints
        $this->checkHeavyEndpoints($request, $findings, $maxScore);

        // Check for excessively long query strings
        $this->checkQueryStringLength($request, $findings, $maxScore);

        // Check for regex DoS patterns in parameters
        $this->checkReDoSPatterns($request, $findings, $maxScore);

        // Check for XML entity expansion
        $this->checkXmlEntityExpansion($request, $findings, $maxScore);

        // Check for excessive number of query parameters
        $this->checkQueryParamCount($request, $findings, $maxScore);

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'Resource exhaustion attempt: %s',
            implode('; ', array_slice(array_unique($findings), 0, 3))
        );

        return new DetectionResult([51, 4], $comment, $maxScore, $this->getName());
    }

    private function checkContentLength(Request $request, array &$findings, int &$maxScore): void
    {
        $contentLength = $request->getHeader('Content-Length');
        if ($contentLength === null) {
            return;
        }

        $length = (int) $contentLength;
        if ($length > self::MAX_CONTENT_LENGTH) {
            $sizeKb = round($length / 1024, 1);
            $findings[] = sprintf('Oversized request body (%s KB)', $sizeKb);

            if ($length > self::MAX_CONTENT_LENGTH * 10) {
                $maxScore = max($maxScore, 80);
            } elseif ($length > self::MAX_CONTENT_LENGTH * 5) {
                $maxScore = max($maxScore, 65);
            } else {
                $maxScore = max($maxScore, 50);
            }
        }
    }

    private function checkHeavyEndpoints(Request $request, array &$findings, int &$maxScore): void
    {
        if (!$request->isPost()) {
            return;
        }

        $uri = $request->getUri();
        foreach (self::HEAVY_ENDPOINTS as $pattern) {
            if (preg_match($pattern, $uri)) {
                $findings[] = 'POST to resource-heavy endpoint (heartbeat)';
                $maxScore = max($maxScore, 45);
                return;
            }
        }
    }

    private function checkQueryStringLength(Request $request, array &$findings, int &$maxScore): void
    {
        $uri = $request->getUri();
        $queryString = parse_url($uri, PHP_URL_QUERY);

        if ($queryString === null || $queryString === false) {
            return;
        }

        $length = strlen($queryString);
        if ($length > self::MAX_QUERY_STRING_LENGTH) {
            $findings[] = sprintf('Excessively long query string (%d chars)', $length);

            if ($length > self::MAX_QUERY_STRING_LENGTH * 4) {
                $maxScore = max($maxScore, 70);
            } else {
                $maxScore = max($maxScore, 55);
            }
        }
    }

    private function checkReDoSPatterns(Request $request, array &$findings, int &$maxScore): void
    {
        $params = $request->getQueryParams();
        $postData = $request->getPostData();

        $allParams = array_merge($params, array_filter($postData, 'is_string'));

        foreach ($allParams as $key => $value) {
            if (!is_string($value) || strlen($value) < 5) {
                continue;
            }

            foreach (self::REDOS_PATTERNS as $pattern) {
                if (preg_match($pattern, $value)) {
                    $findings[] = sprintf('Regex DoS pattern in parameter "%s"', $key);
                    $maxScore = max($maxScore, 60);
                    return;
                }
            }
        }
    }

    private function checkXmlEntityExpansion(Request $request, array &$findings, int &$maxScore): void
    {
        $body = $request->getBody();
        if ($body === '') {
            return;
        }

        foreach (self::XXE_PATTERNS as $pattern) {
            if (preg_match($pattern, $body)) {
                $findings[] = 'XML entity expansion/XXE indicator in request body';
                $maxScore = max($maxScore, 75);
                return;
            }
        }
    }

    private function checkQueryParamCount(Request $request, array &$findings, int &$maxScore): void
    {
        $paramCount = count($request->getQueryParams());

        if ($paramCount > self::MAX_QUERY_PARAMS) {
            $findings[] = sprintf('Excessive query parameters (%d params)', $paramCount);

            if ($paramCount > self::MAX_QUERY_PARAMS * 4) {
                $maxScore = max($maxScore, 70);
            } else {
                $maxScore = max($maxScore, 50);
            }
        }
    }
}
