<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;
use ReportedIp\Honeypot\Detection\PatternLibrary;

/**
 * Detects brute force login attempts.
 *
 * In a honeypot context, ANY login attempt is suspicious. This analyzer checks
 * for POST requests to known login endpoints and common username/password fields.
 * Also tracks request frequency from the same IP using a simple file-based counter.
 */
final class BruteForceAnalyzer implements AnalyzerInterface
{
    /** Known login endpoint path patterns. */
    private const LOGIN_PATHS = [
        '/\/wp-login\.php/i',
        '/\/wp-admin\/?$/i',
        '/\/administrator\/?$/i',
        '/\/admin\/login/i',
        '/\/user\/login/i',
        '/\/login\/?$/i',
        '/\/signin\/?$/i',
        '/\/auth\/login/i',
        '/\/account\/login/i',
        '/\/api\/auth/i',
        '/\/api\/login/i',
    ];

    /** Form field names commonly used for username/password. */
    private const USERNAME_FIELDS = ['log', 'username', 'user', 'user_login', 'email', 'login', 'name', 'usr'];
    private const PASSWORD_FIELDS = ['pwd', 'password', 'pass', 'user_pass', 'passwd', 'user_password', 'secret'];

    private ?string $counterDir;

    public function __construct(?string $counterDir = null)
    {
        $this->counterDir = $counterDir ?? sys_get_temp_dir() . '/honeypot_brute_counters';
    }

    public function getName(): string
    {
        return 'BruteForce';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $findings = [];
        $maxScore = 0;

        $path = $request->getPath();
        $isLoginEndpoint = $this->isLoginEndpoint($path);

        // POST to a login endpoint
        if ($request->isPost() && $isLoginEndpoint) {
            $findings[] = sprintf('POST to login endpoint: %s', $path);
            $maxScore = max($maxScore, 60);

            $postData = $request->getPostData();

            // Check for known username/password field combinations
            $username = $this->extractField($postData, self::USERNAME_FIELDS);
            $password = $this->extractField($postData, self::PASSWORD_FIELDS);

            if ($username !== null) {
                $commonUsernames = PatternLibrary::commonUsernames();
                if (in_array(strtolower($username), $commonUsernames, true)) {
                    $findings[] = sprintf('Common username attempted: %s', $username);
                    $maxScore = max($maxScore, 75);
                } else {
                    $findings[] = sprintf('Login username: %s', substr($username, 0, 50));
                    $maxScore = max($maxScore, 65);
                }
            }

            if ($password !== null) {
                $commonPasswords = PatternLibrary::commonPasswords();
                if (in_array($password, $commonPasswords, true)) {
                    $findings[] = sprintf('Common/default password attempted');
                    $maxScore = max($maxScore, 80);
                }
            }

            // Check for rapid attempts from same IP
            $repeatCount = $this->trackAttempt($request->getIp());
            if ($repeatCount > 3) {
                $findings[] = sprintf('Repeated login attempts from same IP (%d attempts)', $repeatCount);
                $maxScore = max($maxScore, 85);
            }
        }

        // GET to login endpoints can also indicate scanning
        if ($request->isGet() && $isLoginEndpoint) {
            $findings[] = sprintf('Login page probe: %s', $path);
            $maxScore = max($maxScore, 40);

            // Don't return for simple GETs to login - too common
            // Only flag if there are additional signals
            $queryParams = $request->getQueryParams();
            if (!empty($queryParams)) {
                $findings[] = 'Login endpoint probed with query parameters';
                $maxScore = max($maxScore, 50);
            } else {
                // Simple GET to login page alone isn't strong enough signal
                return null;
            }
        }

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'Brute force attempt detected: %s',
            implode('; ', array_slice($findings, 0, 3))
        );

        return new DetectionResult([18, 31], $comment, $maxScore, $this->getName());
    }

    private function isLoginEndpoint(string $path): bool
    {
        foreach (self::LOGIN_PATHS as $pattern) {
            if (preg_match($pattern, $path)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extract a field value from POST data by checking multiple possible field names.
     *
     * @param array<string, mixed> $postData
     * @param string[] $fieldNames
     */
    private function extractField(array $postData, array $fieldNames): ?string
    {
        foreach ($fieldNames as $field) {
            if (isset($postData[$field]) && is_string($postData[$field]) && $postData[$field] !== '') {
                return $postData[$field];
            }
        }
        return null;
    }

    /**
     * Track login attempts per IP using a simple file-based counter.
     * Returns the number of attempts in the current time window (5 minutes).
     */
    private function trackAttempt(string $ip): int
    {
        if (!is_dir($this->counterDir)) {
            @mkdir($this->counterDir, 0750, true);
        }

        $file = $this->counterDir . '/' . md5($ip) . '.count';
        $window = 300; // 5-minute window

        $attempts = [];
        $now = time();

        if (file_exists($file)) {
            $content = @file_get_contents($file);
            if ($content !== false) {
                $attempts = array_filter(
                    explode("\n", trim($content)),
                    static fn(string $ts) => $ts !== '' && ($now - (int) $ts) < $window
                );
            }
        }

        $attempts[] = (string) $now;
        @file_put_contents($file, implode("\n", $attempts));

        return count($attempts);
    }
}
