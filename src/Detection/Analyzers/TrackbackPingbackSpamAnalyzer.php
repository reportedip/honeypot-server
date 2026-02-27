<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;
use ReportedIp\Honeypot\Detection\PatternLibrary;

/**
 * Detects trackback and pingback spam and abuse.
 *
 * Checks for POST requests to trackback/pingback endpoints, multiple URLs
 * in payload data, DDoS amplification via pingback, XML pingback/trackback
 * elements, and spam keywords in trackback content.
 */
final class TrackbackPingbackSpamAnalyzer implements AnalyzerInterface
{
    private const URL_PATTERN = '/https?:\/\/[^\s<>"\']+/i';
    private const MAX_URLS_ALLOWED = 3;

    public function getName(): string
    {
        return 'TrackbackPingbackSpam';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        if (!$request->isPost()) {
            return null;
        }

        $path = strtolower($request->getPath());
        $body = $request->getBody();
        $bodyLower = strtolower($body);

        $findings = [];
        $maxScore = 0;

        $isTrackback = (bool) preg_match('/\/wp-trackback\.php/i', $path);
        $isPingback = str_contains($path, 'xmlrpc.php') && str_contains($bodyLower, 'pingback.ping');

        if (!$isTrackback && !$isPingback) {
            // Also check for standalone trackback/pingback paths
            if (!preg_match('/\/trackback\/?$/i', $path) && !preg_match('/\/pingback\/?$/i', $path)) {
                return null;
            }
        }

        // POST to trackback endpoint
        if ($isTrackback || preg_match('/\/trackback\/?$/i', $path)) {
            $findings[] = sprintf('POST to trackback endpoint: %s', $path);
            $maxScore = max($maxScore, 55);
        }

        // POST to xmlrpc.php with pingback.ping
        if ($isPingback) {
            $findings[] = 'pingback.ping request via XML-RPC';
            $maxScore = max($maxScore, 60);
        }

        // Check for multiple URLs in body (spam indicator)
        preg_match_all(self::URL_PATTERN, $body, $urlMatches);
        $urlCount = count($urlMatches[0] ?? []);
        if ($urlCount > self::MAX_URLS_ALLOWED) {
            $findings[] = sprintf('Excessive URLs in trackback/pingback data (%d URLs)', $urlCount);
            $maxScore = max($maxScore, 65);
        }

        // Check for pingback to external URLs (DDoS amplification)
        if ($isPingback && preg_match('/https?:\/\/[^\s<>"\']+/i', $body)) {
            // Look for external target URL in pingback payload
            if (preg_match('/<string>\s*(https?:\/\/[^<]+)\s*<\/string>/i', $body, $matches)) {
                $findings[] = sprintf('Pingback to external URL (DDoS amplification): %s', substr($matches[1], 0, 100));
                $maxScore = max($maxScore, 75);
            }
        }

        // Check for XML pingback/trackback elements
        if (preg_match('/<pingback>/i', $body)) {
            $findings[] = 'XML <pingback> element detected';
            $maxScore = max($maxScore, 55);
        }

        if (preg_match('/<trackback>/i', $body)) {
            $findings[] = 'XML <trackback> element detected';
            $maxScore = max($maxScore, 55);
        }

        // Check for spam keywords in trackback content
        $spamPatterns = PatternLibrary::spamKeywords();
        $spamMatches = 0;
        foreach ($spamPatterns as $pattern) {
            if (preg_match($pattern, $body)) {
                $spamMatches++;
            }
        }

        if ($spamMatches >= 2) {
            $findings[] = sprintf('Spam keywords in trackback/pingback content (%d matches)', $spamMatches);
            $maxScore = max($maxScore, 70);
        } elseif ($spamMatches === 1) {
            $findings[] = 'Spam keyword in trackback/pingback content';
            $maxScore = max($maxScore, 55);
        }

        if (empty($findings)) {
            return null;
        }

        // Cap score at 75
        $maxScore = min(75, $maxScore);

        $comment = sprintf(
            'Trackback/pingback spam detected: %s',
            implode('; ', array_slice(array_unique($findings), 0, 3))
        );

        return new DetectionResult([42, 12], $comment, $maxScore, $this->getName());
    }
}
