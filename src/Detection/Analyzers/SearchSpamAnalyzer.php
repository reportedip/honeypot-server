<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;
use ReportedIp\Honeypot\Detection\PatternLibrary;

/**
 * Detects abuse of CMS search functionality.
 *
 * Checks search query parameters for SQL injection, XSS, path traversal,
 * excessively long queries, spam keywords, and special character abuse.
 */
final class SearchSpamAnalyzer implements AnalyzerInterface
{
    /** Maximum reasonable search query length. */
    private const MAX_SEARCH_LENGTH = 200;

    /** Special characters that indicate attack patterns in search queries. */
    private const SUSPICIOUS_CHARS = ['<', '>', '{', '}', '|', '\\'];

    /** Query parameter names used by CMS search features. */
    private const SEARCH_PARAMS = ['s', 'q', 'query', 'search', 'keyword', 'keywords', 'searchword'];

    public function getName(): string
    {
        return 'SearchSpam';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        if (!$request->isGet()) {
            return null;
        }

        $queryParams = $request->getQueryParams();
        if (empty($queryParams)) {
            return null;
        }

        // Find the search query value
        $searchQuery = null;
        $searchParam = null;
        foreach (self::SEARCH_PARAMS as $param) {
            $value = $request->getQueryParam($param);
            if ($value !== null && $value !== '') {
                $searchQuery = $value;
                $searchParam = $param;
                break;
            }
        }

        if ($searchQuery === null) {
            return null;
        }

        $findings = [];
        $maxScore = 0;

        // Check for SQL injection patterns in search query
        $sqlPatterns = PatternLibrary::sqlInjectionPatterns();
        foreach ($sqlPatterns as $pattern) {
            if (preg_match($pattern, $searchQuery)) {
                $findings[] = 'SQL injection pattern in search query';
                $maxScore = max($maxScore, 75);
                break;
            }
        }

        // Check for XSS patterns in search query
        $xssPatterns = PatternLibrary::xssPatterns();
        foreach ($xssPatterns as $pattern) {
            if (preg_match($pattern, $searchQuery)) {
                $findings[] = 'XSS pattern in search query';
                $maxScore = max($maxScore, 70);
                break;
            }
        }

        // Check for path traversal in search query
        $traversalPatterns = PatternLibrary::pathTraversalPatterns();
        foreach ($traversalPatterns as $pattern) {
            if (preg_match($pattern, $searchQuery)) {
                $findings[] = 'Path traversal attempt in search query';
                $maxScore = max($maxScore, 70);
                break;
            }
        }

        // Check for excessively long search queries
        if (mb_strlen($searchQuery) > self::MAX_SEARCH_LENGTH) {
            $findings[] = sprintf('Excessively long search query (%d chars)', mb_strlen($searchQuery));
            $maxScore = max($maxScore, 55);
        }

        // Check for spam keywords in search query
        $spamPatterns = PatternLibrary::spamKeywords();
        $spamMatches = 0;
        foreach ($spamPatterns as $pattern) {
            if (preg_match($pattern, $searchQuery)) {
                $spamMatches++;
            }
        }

        if ($spamMatches >= 2) {
            $findings[] = sprintf('Multiple spam keywords in search (%d matches)', $spamMatches);
            $maxScore = max($maxScore, 60);
        } elseif ($spamMatches === 1) {
            $findings[] = 'Spam keyword in search query';
            $maxScore = max($maxScore, 40);
        }

        // Check for suspicious special characters in search query
        $specialCharCount = 0;
        foreach (self::SUSPICIOUS_CHARS as $char) {
            $specialCharCount += substr_count($searchQuery, $char);
        }

        if ($specialCharCount >= 3) {
            $findings[] = sprintf('Multiple special characters in search query (%d)', $specialCharCount);
            $maxScore = max($maxScore, 55);
        }

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'Search abuse detected (%s=%s): %s',
            $searchParam,
            substr($searchQuery, 0, 100),
            implode('; ', array_slice(array_unique($findings), 0, 3))
        );

        return new DetectionResult([53], $comment, $maxScore, $this->getName());
    }
}
