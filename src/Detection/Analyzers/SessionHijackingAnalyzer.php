<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;

/**
 * Detects session hijacking and cookie manipulation attempts.
 *
 * Checks for suspicious cookie patterns (admin privilege escalation),
 * WordPress session cookie manipulation, session fixation via URL,
 * cookie injection via CRLF, abnormally long cookies, and malformed
 * JWT tokens.
 */
final class SessionHijackingAnalyzer implements AnalyzerInterface
{
    /** Maximum reasonable cookie header size in bytes. */
    private const MAX_COOKIE_SIZE = 4096;

    /** Suspicious cookie patterns indicating privilege escalation attempts. */
    private const SUSPICIOUS_COOKIE_PATTERNS = [
        '/\badmin\s*=\s*(1|true|yes)\b/i',
        '/\brole\s*=\s*(admin|administrator|root|superadmin)\b/i',
        '/\bis_admin\s*=\s*(1|true|yes)\b/i',
        '/\bisadmin\s*=\s*(1|true|yes)\b/i',
        '/\buser_role\s*=\s*(admin|administrator|root)\b/i',
        '/\baccess_level\s*=\s*(admin|root|super)\b/i',
        '/\bprivileged\s*=\s*(1|true|yes)\b/i',
        '/\bstaff\s*=\s*(1|true)\b/i',
    ];

    /** Session fixation parameter names. */
    private const SESSION_PARAMS = ['PHPSESSID', 'session_id', 'sid', 'sessid', 'JSESSIONID', 'ASP.NET_SessionId'];

    public function getName(): string
    {
        return 'SessionHijacking';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $findings = [];
        $maxScore = 0;

        $cookieHeader = $request->getHeader('Cookie');
        $cookies = $request->getCookies();
        $queryParams = $request->getQueryParams();
        $headers = $request->getHeaders();

        // Check for suspicious admin/privilege cookies
        if ($cookieHeader !== null && $cookieHeader !== '') {
            foreach (self::SUSPICIOUS_COOKIE_PATTERNS as $pattern) {
                if (preg_match($pattern, $cookieHeader)) {
                    $findings[] = sprintf(
                        'Suspicious privilege cookie pattern: %s',
                        $this->describePattern($pattern)
                    );
                    $maxScore = max($maxScore, 65);
                    break;
                }
            }

            // WordPress logged-in cookie with suspicious values
            foreach ($cookies as $name => $value) {
                if (preg_match('/^wordpress_logged_in_/i', $name)) {
                    // WordPress logged_in cookie format: username|expiration|token|hash
                    // Suspicious if it contains obviously crafted values
                    if (preg_match('/^(admin|administrator|root)\|/i', $value) ||
                        preg_match('/\|0{5,}\|/', $value) ||
                        mb_strlen($value) < 10) {
                        $findings[] = sprintf(
                            'Suspicious wordpress_logged_in cookie value for cookie "%s"',
                            substr($name, 0, 50)
                        );
                        $maxScore = max($maxScore, 70);
                    }
                    break;
                }
            }

            // Abnormally long cookie values
            if (mb_strlen($cookieHeader) > self::MAX_COOKIE_SIZE) {
                $findings[] = sprintf(
                    'Abnormally large Cookie header (%d bytes)',
                    mb_strlen($cookieHeader)
                );
                $maxScore = max($maxScore, 55);
            }
        }

        // Session fixation via URL parameters
        foreach ($queryParams as $key => $val) {
            foreach (self::SESSION_PARAMS as $sessionParam) {
                if (strcasecmp($key, $sessionParam) === 0) {
                    $findings[] = sprintf('Session fixation attempt via URL parameter "%s"', $key);
                    $maxScore = max($maxScore, 70);
                    break 2;
                }
            }
        }

        // Cookie injection via CRLF in any header value
        foreach ($headers as $name => $value) {
            $headerValue = is_string($value) ? $value : (string) $value;
            if (preg_match('/(\r\n|\r|\n|%0[dD]%0[aA])Set-Cookie\s*:/i', $headerValue)) {
                $findings[] = sprintf('Cookie injection via CRLF in header "%s"', $name);
                $maxScore = max($maxScore, 75);
                break;
            }
        }

        // Check for malformed JWT tokens in cookies
        foreach ($cookies as $name => $value) {
            if ($this->looksLikeJwt($value) && !$this->isValidJwtStructure($value)) {
                $findings[] = sprintf('Malformed JWT token in cookie "%s"', substr($name, 0, 50));
                $maxScore = max($maxScore, 55);
                break;
            }
        }

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'Session hijacking/manipulation detected: %s',
            implode('; ', array_slice($findings, 0, 3))
        );

        return new DetectionResult([14, 15], $comment, $maxScore, $this->getName());
    }

    /**
     * Check if a value looks like it could be an attempted JWT token.
     */
    private function looksLikeJwt(string $value): bool
    {
        // JWTs have dots and use base64-like characters, are reasonably long
        return mb_strlen($value) > 20 && substr_count($value, '.') >= 1 &&
            preg_match('/^[A-Za-z0-9_\-]+\./', $value) === 1;
    }

    /**
     * Check if a JWT has valid structural format (3 dot-separated base64url parts).
     */
    private function isValidJwtStructure(string $value): bool
    {
        $parts = explode('.', $value);
        if (count($parts) !== 3) {
            return false;
        }

        foreach ($parts as $part) {
            // Each part must be valid base64url encoding
            if ($part === '') {
                return false;
            }
            if (!preg_match('/^[A-Za-z0-9_\-]+$/', $part)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Describe a suspicious cookie pattern for the detection comment.
     */
    private function describePattern(string $pattern): string
    {
        $map = [
            'admin\s*=' => 'admin flag cookie',
            'role\s*=' => 'role elevation cookie',
            'is_admin' => 'is_admin flag cookie',
            'isadmin' => 'isadmin flag cookie',
            'user_role' => 'user_role elevation cookie',
            'access_level' => 'access_level elevation cookie',
            'privileged' => 'privileged flag cookie',
            'staff' => 'staff flag cookie',
        ];

        foreach ($map as $keyword => $description) {
            if (preg_match('/' . $keyword . '/i', $pattern)) {
                return $description;
            }
        }

        return 'privilege escalation cookie';
    }
}
