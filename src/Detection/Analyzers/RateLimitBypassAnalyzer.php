<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;

/**
 * Detects attempts to bypass rate limiting via header manipulation.
 *
 * Checks for spoofed X-Forwarded-For headers with fake IPs, excessive
 * proxy chains, mismatched X-Real-IP headers, presence of uncommon
 * IP-spoofing headers, and unusual Via proxy chains.
 */
final class RateLimitBypassAnalyzer implements AnalyzerInterface
{
    /** IP-related headers commonly used for rate limit bypass. */
    private const IP_HEADERS = [
        'X-Forwarded-For',
        'X-Real-Ip',
        'X-Originating-Ip',
        'True-Client-Ip',
        'Cf-Connecting-Ip',
        'X-Client-Ip',
        'X-Cluster-Client-Ip',
        'Forwarded-For',
        'X-Forwarded',
        'Forwarded',
    ];

    /** Maximum reasonable number of IPs in a forwarding chain. */
    private const MAX_PROXY_CHAIN_LENGTH = 3;

    /** Patterns for obviously fake/spoofed IPs. */
    private const FAKE_IP_PATTERNS = [
        '/^127\./',                // Loopback
        '/^0\.0\.0\.0$/',          // Unspecified
        '/^0\./',                  // Zero network
        '/^localhost$/i',          // Localhost string
        '/^::1$/',                 // IPv6 loopback
        '/^::$/',                  // IPv6 unspecified
        '/^192\.168\./',           // Private range
        '/^10\./',                 // Private range
        '/^172\.(1[6-9]|2\d|3[01])\./', // Private range
        '/^169\.254\./',           // Link-local
        '/^fc[0-9a-f]{2}:/i',     // IPv6 unique local
        '/^fe80:/i',              // IPv6 link-local
        '/^255\.255\.255\.255$/',  // Broadcast
        '/^0{1,3}\.0{1,3}\.0{1,3}\.0{1,3}$/', // Zero variants
    ];

    public function getName(): string
    {
        return 'RateLimitBypass';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $findings = [];
        $maxScore = 0;

        $headers = $request->getHeaders();

        // Check X-Forwarded-For header
        $xff = $request->getHeader('X-Forwarded-For');
        if ($xff !== null && $xff !== '') {
            $ips = array_map('trim', explode(',', $xff));

            // Check for obviously fake/spoofed IPs
            foreach ($ips as $ip) {
                if ($this->isFakeIp($ip)) {
                    $findings[] = sprintf(
                        'X-Forwarded-For contains suspicious IP: %s',
                        substr($ip, 0, 45)
                    );
                    $maxScore = max($maxScore, 50);
                    break;
                }
            }

            // Excessive proxy chain length
            if (count($ips) > self::MAX_PROXY_CHAIN_LENGTH) {
                $findings[] = sprintf(
                    'Excessive X-Forwarded-For chain (%d IPs)',
                    count($ips)
                );
                $maxScore = max($maxScore, 45);
            }

            // Multiple private IPs in X-Forwarded-For suggesting rotation
            $privateCount = 0;
            foreach ($ips as $ip) {
                if ($this->isPrivateIp($ip)) {
                    $privateCount++;
                }
            }
            if ($privateCount >= 2) {
                $findings[] = sprintf(
                    'Multiple private IPs in X-Forwarded-For chain (%d private IPs)',
                    $privateCount
                );
                $maxScore = max($maxScore, 50);
            }
        }

        // Check X-Real-IP
        $xRealIp = $request->getHeader('X-Real-Ip');
        if ($xRealIp !== null && $xRealIp !== '') {
            if ($this->isFakeIp(trim($xRealIp))) {
                $findings[] = sprintf('X-Real-IP contains suspicious IP: %s', substr($xRealIp, 0, 45));
                $maxScore = max($maxScore, 50);
            }

            // X-Real-IP differing from connection IP
            $connectionIp = $request->getIp();
            if (trim($xRealIp) !== $connectionIp && !$this->isSameSubnet($xRealIp, $connectionIp)) {
                $findings[] = sprintf(
                    'X-Real-IP (%s) differs significantly from connection IP',
                    substr($xRealIp, 0, 45)
                );
                $maxScore = max($maxScore, 45);
            }
        }

        // Check for uncommon IP-spoofing headers (often added by attackers)
        $spoofHeaders = ['X-Originating-Ip', 'True-Client-Ip', 'X-Client-Ip', 'X-Cluster-Client-Ip'];
        foreach ($spoofHeaders as $headerName) {
            $headerVal = $request->getHeader($headerName);
            if ($headerVal !== null && $headerVal !== '') {
                $findings[] = sprintf(
                    'Uncommon IP header present: %s = %s',
                    $headerName,
                    substr($headerVal, 0, 45)
                );
                $maxScore = max($maxScore, 40);
            }
        }

        // Check CF-Connecting-IP when not likely from Cloudflare
        $cfIp = $request->getHeader('Cf-Connecting-Ip');
        if ($cfIp !== null && $cfIp !== '') {
            // In a honeypot context, presence of CF-Connecting-IP without other CF headers
            // suggests header spoofing
            $cfRay = $request->getHeader('Cf-Ray');
            if ($cfRay === null || $cfRay === '') {
                $findings[] = sprintf(
                    'CF-Connecting-IP without CF-Ray header (likely spoofed): %s',
                    substr($cfIp, 0, 45)
                );
                $maxScore = max($maxScore, 55);
            }
        }

        // Check Via header for unusual proxy chains
        $via = $request->getHeader('Via');
        if ($via !== null && $via !== '') {
            $proxyCount = substr_count($via, ',') + 1;
            if ($proxyCount > 3) {
                $findings[] = sprintf('Unusual Via proxy chain (%d proxies)', $proxyCount);
                $maxScore = max($maxScore, 40);
            }

            // Via header with suspicious content
            if (preg_match('/[<>"\';]/', $via)) {
                $findings[] = 'Suspicious characters in Via header';
                $maxScore = max($maxScore, 45);
            }
        }

        // Multiple IP-related headers present = stronger signal
        $ipHeaderCount = 0;
        foreach (self::IP_HEADERS as $header) {
            if ($request->getHeader($header) !== null) {
                $ipHeaderCount++;
            }
        }
        if ($ipHeaderCount >= 4) {
            $findings[] = sprintf('Excessive IP-related headers present (%d headers)', $ipHeaderCount);
            $maxScore = max($maxScore, 60);
        }

        // Cap maximum score within the defined range
        $maxScore = min($maxScore, 65);

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'Rate limit bypass attempt detected: %s',
            implode('; ', array_slice($findings, 0, 3))
        );

        return new DetectionResult([15, 19], $comment, $maxScore, $this->getName());
    }

    /**
     * Check if an IP address appears to be fake/spoofed.
     */
    private function isFakeIp(string $ip): bool
    {
        $ip = trim($ip);
        foreach (self::FAKE_IP_PATTERNS as $pattern) {
            if (preg_match($pattern, $ip)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if an IP is in a private range.
     */
    private function isPrivateIp(string $ip): bool
    {
        $ip = trim($ip);
        return (bool) preg_match('/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|fc|fd|fe80:)/i', $ip);
    }

    /**
     * Check if two IPs are in the same /16 subnet (very rough check).
     */
    private function isSameSubnet(string $ip1, string $ip2): bool
    {
        $ip1 = trim($ip1);
        $ip2 = trim($ip2);

        $parts1 = explode('.', $ip1);
        $parts2 = explode('.', $ip2);

        if (count($parts1) < 2 || count($parts2) < 2) {
            return false;
        }

        return $parts1[0] === $parts2[0] && $parts1[1] === $parts2[1];
    }
}
