<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;
use ReportedIp\Honeypot\Detection\PatternLibrary;

/**
 * Detects Server-Side Request Forgery (SSRF) attempts.
 *
 * Checks URI and query parameters for internal IP addresses, localhost variants,
 * cloud metadata endpoints, and dangerous protocol handlers.
 */
final class SsrfAnalyzer implements AnalyzerInterface
{
    public function getName(): string
    {
        return 'SSRF';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $findings = [];
        $maxScore = 0;

        $targets = [];
        $targets['URI'] = $request->getUri();

        foreach ($request->getQueryParams() as $key => $val) {
            $targets["query param '{$key}'"] = is_string($val) ? $val : (string) $val;
        }

        foreach ($request->getPostData() as $key => $val) {
            $targets["POST field '{$key}'"] = is_string($val) ? $val : (string) $val;
        }

        $patterns = PatternLibrary::ssrfPatterns();

        foreach ($targets as $label => $value) {
            if ($value === '' || mb_strlen($value) < 4) {
                continue;
            }

            $decoded = urldecode($value);

            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $value) || preg_match($pattern, $decoded)) {
                    $score = $this->scorePattern($pattern);
                    $maxScore = max($maxScore, $score);
                    $findings[] = sprintf(
                        'SSRF indicator in %s: %s',
                        $label,
                        $this->describePattern($pattern)
                    );
                    break;
                }
            }
        }

        // Additional check: URL-valued parameters pointing to internal resources
        $urlParamNames = ['url', 'redirect', 'next', 'target', 'dest', 'return', 'goto', 'link', 'proxy', 'site', 'path', 'uri', 'callback'];
        foreach ($request->getQueryParams() as $key => $val) {
            if (in_array(strtolower($key), $urlParamNames, true) && is_string($val) && $val !== '') {
                $decodedVal = urldecode($val);
                if ($this->isInternalUrl($decodedVal)) {
                    $findings[] = sprintf(
                        'URL parameter "%s" points to internal resource: %s',
                        $key,
                        substr($decodedVal, 0, 100)
                    );
                    $maxScore = max($maxScore, 80);
                }
            }
        }

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'SSRF attempt detected: %s',
            implode('; ', array_slice($findings, 0, 3))
        );

        return new DetectionResult([21], $comment, $maxScore, $this->getName());
    }

    private function isInternalUrl(string $url): bool
    {
        $internalPatterns = [
            '/^https?:\/\/(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|localhost|0\.0\.0\.0|\[?::1\]?|169\.254\.169\.254)/i',
            '/^(file|dict|gopher|ldap|sftp|tftp):\/\//i',
        ];

        foreach ($internalPatterns as $pattern) {
            if (preg_match($pattern, $url)) {
                return true;
            }
        }

        return false;
    }

    private function scorePattern(string $pattern): int
    {
        // Cloud metadata
        if (preg_match('/169\.254\.169\.254|metadata\.(google|aws)/i', $pattern)) {
            return 85;
        }

        // Dangerous protocols
        if (preg_match('/file:\/\/|gopher:\/\/|dict:\/\/|ldap:\/\//i', $pattern)) {
            return 80;
        }

        // Loopback/localhost
        if (preg_match('/127\.|localhost|0\.0\.0\.0|::1/i', $pattern)) {
            return 70;
        }

        // Private IP ranges
        if (preg_match('/10\.|192\.168\.|172\./i', $pattern)) {
            return 65;
        }

        // URL params with URLs
        if (preg_match('/url|redirect|next|target/i', $pattern)) {
            return 60;
        }

        return 65;
    }

    private function describePattern(string $pattern): string
    {
        $map = [
            '169\.254\.169\.254|metadata' => 'cloud metadata endpoint access',
            '127\.|localhost|0\.0\.0\.0|::1' => 'loopback/localhost access',
            '10\.|192\.168\.|172\.' => 'private network access',
            '169\.254\.' => 'link-local address access',
            'file:\/\/' => 'file protocol access',
            'gopher:\/\/' => 'gopher protocol abuse',
            'dict:\/\/' => 'dict protocol abuse',
            'ldap:\/\/' => 'LDAP protocol abuse',
            'sftp:\/\/|tftp:\/\/' => 'file transfer protocol abuse',
            'url|redirect|next|target|dest' => 'URL parameter with redirect',
            '0x[0-9a-f]|0[0-7]' => 'encoded IP address',
            'http:\/\/0\/' => 'shortened localhost variant',
        ];

        foreach ($map as $keyword => $description) {
            if (preg_match('/' . $keyword . '/i', $pattern)) {
                return $description;
            }
        }

        return 'SSRF indicator';
    }
}
