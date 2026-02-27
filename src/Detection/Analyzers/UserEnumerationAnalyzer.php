<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;

/**
 * Detects WordPress user enumeration attempts.
 *
 * Covers author query parameter probing, author archive path access,
 * REST API user endpoint access, sitemap user paths, rest_route
 * parameter enumeration, and oEmbed author info probing.
 */
final class UserEnumerationAnalyzer implements AnalyzerInterface
{
    public function getName(): string
    {
        return 'UserEnumeration';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $path = $request->getPath();
        $uri = $request->getUri();

        $findings = [];
        $maxScore = 0;

        // Check author query parameter with numeric value
        $this->checkAuthorParam($request, $findings, $maxScore);

        // Check /author/{name} path access
        $this->checkAuthorPath($path, $findings, $maxScore);

        // Check REST API users endpoint
        $this->checkRestApiUsers($path, $findings, $maxScore);

        // Check sitemap user paths
        $this->checkSitemapUsers($path, $findings, $maxScore);

        // Check /?rest_route=/wp/v2/users
        $this->checkRestRoute($request, $findings, $maxScore);

        // Check /wp-json/oembed with author info
        $this->checkOembedAuthor($path, $uri, $findings, $maxScore);

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'User enumeration attempt: %s (path: %s)',
            implode('; ', array_slice(array_unique($findings), 0, 3)),
            substr($uri, 0, 200)
        );

        return new DetectionResult([55, 15], $comment, $maxScore, $this->getName());
    }

    private function checkAuthorParam(Request $request, array &$findings, int &$maxScore): void
    {
        $authorParam = $request->getQueryParam('author');
        if ($authorParam !== null && preg_match('/^\d+$/', $authorParam)) {
            $findings[] = sprintf('Author ID enumeration via query parameter (author=%s)', $authorParam);
            $maxScore = max($maxScore, 65);
        }
    }

    private function checkAuthorPath(string $path, array &$findings, int &$maxScore): void
    {
        if (preg_match('#^/author/([^/]+)/?$#i', $path, $matches)) {
            $findings[] = sprintf('Author archive access: /author/%s', substr($matches[1], 0, 50));
            $maxScore = max($maxScore, 55);
        }
    }

    private function checkRestApiUsers(string $path, array &$findings, int &$maxScore): void
    {
        if (preg_match('#/wp-json/wp/v2/users#i', $path)) {
            $findings[] = 'WordPress REST API user enumeration (/wp-json/wp/v2/users)';
            $maxScore = max($maxScore, 80);
        }
    }

    private function checkSitemapUsers(string $path, array &$findings, int &$maxScore): void
    {
        $pathLower = strtolower($path);

        if (str_contains($pathLower, 'wp-sitemap-users') || str_contains($pathLower, 'author-sitemap')) {
            $findings[] = 'User enumeration via sitemap path';
            $maxScore = max($maxScore, 65);
        }
    }

    private function checkRestRoute(Request $request, array &$findings, int &$maxScore): void
    {
        $restRoute = $request->getQueryParam('rest_route');
        if ($restRoute !== null && preg_match('#/wp/v2/users#i', $restRoute)) {
            $findings[] = 'WordPress REST API user enumeration via rest_route parameter';
            $maxScore = max($maxScore, 80);
        }
    }

    private function checkOembedAuthor(string $path, string $uri, array &$findings, int &$maxScore): void
    {
        if (preg_match('#/wp-json/oembed#i', $path)) {
            // oEmbed requests can leak author information
            if (preg_match('/author/i', $uri)) {
                $findings[] = 'oEmbed author info probing';
                $maxScore = max($maxScore, 60);
            } else {
                $findings[] = 'oEmbed endpoint access (potential author info leakage)';
                $maxScore = max($maxScore, 55);
            }
        }
    }
}
