<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;
use ReportedIp\Honeypot\Detection\PatternLibrary;

/**
 * Detects password reset abuse attempts.
 *
 * Checks for requests to password reset endpoints across WordPress, Drupal,
 * and Joomla. Detects common username targeting, Host header injection in
 * password resets, and multiple password reset indicators in a single request.
 */
final class PasswordResetAbuseAnalyzer implements AnalyzerInterface
{
    /** Password reset endpoint patterns for various CMS platforms. */
    private const RESET_PATHS = [
        'wordpress' => '/\/wp-login\.php/i',
        'drupal'    => '/\/user\/password\/?$/i',
        'joomla'    => '/\/\?option=com_users&task=user\.remind/i',
    ];

    /** WordPress password reset action values. */
    private const WP_RESET_ACTIONS = ['lostpassword', 'retrievepassword', 'resetpass', 'rp'];

    /** Form field names for username/email in password reset forms. */
    private const USERNAME_FIELDS = ['user_login', 'log', 'username', 'user', 'email', 'name', 'login'];

    public function getName(): string
    {
        return 'PasswordResetAbuse';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $findings = [];
        $maxScore = 0;

        $path = $request->getPath();
        $uri = $request->getUri();
        $queryParams = $request->getQueryParams();
        $postData = $request->getPostData();

        $isPasswordResetRequest = false;

        // WordPress: /wp-login.php?action=lostpassword
        if (preg_match(self::RESET_PATHS['wordpress'], $path)) {
            $action = $queryParams['action'] ?? null;
            if ($action !== null && in_array(strtolower($action), self::WP_RESET_ACTIONS, true)) {
                $isPasswordResetRequest = true;
                $findings[] = sprintf('WordPress password reset request (action=%s)', $action);
                $maxScore = max($maxScore, 50);
            }

            // POST to wp-login.php with lostpassword action
            if ($request->isPost()) {
                $postAction = $postData['action'] ?? null;
                if (is_string($postAction) && in_array(strtolower($postAction), self::WP_RESET_ACTIONS, true)) {
                    $isPasswordResetRequest = true;
                    $findings[] = 'WordPress password reset POST submission';
                    $maxScore = max($maxScore, 55);
                }
            }
        }

        // Drupal: POST to /user/password
        if (preg_match(self::RESET_PATHS['drupal'], $path)) {
            $isPasswordResetRequest = true;
            $findings[] = 'Drupal password reset endpoint accessed';
            $maxScore = max($maxScore, 50);

            if ($request->isPost()) {
                $findings[] = 'Drupal password reset POST submission';
                $maxScore = max($maxScore, 55);
            }
        }

        // Joomla: ?option=com_users&task=user.remind
        if (preg_match('/option=com_users/i', $uri) && preg_match('/task=user\.remind/i', $uri)) {
            $isPasswordResetRequest = true;
            $findings[] = 'Joomla password reset endpoint accessed';
            $maxScore = max($maxScore, 50);

            if ($request->isPost()) {
                $findings[] = 'Joomla password reset POST submission';
                $maxScore = max($maxScore, 55);
            }
        }

        if (!$isPasswordResetRequest) {
            return null;
        }

        // Check for common usernames in POST data
        if ($request->isPost()) {
            $submittedUsername = $this->extractUsername($postData);
            if ($submittedUsername !== null) {
                $commonUsernames = PatternLibrary::commonUsernames();
                if (in_array(strtolower($submittedUsername), $commonUsernames, true)) {
                    $findings[] = sprintf('Password reset for common username: %s', $submittedUsername);
                    $maxScore = max($maxScore, 65);
                }
            }
        }

        // Host header injection detection
        $hostHeader = $request->getHeader('Host');
        if ($hostHeader !== null) {
            // Multiple Host values or unusual characters
            if (preg_match('/,/', $hostHeader) ||
                preg_match('/\s/', $hostHeader) ||
                preg_match('/@/', $hostHeader)) {
                $findings[] = sprintf('Suspicious Host header in password reset: %s', substr($hostHeader, 0, 80));
                $maxScore = max($maxScore, 70);
            }

            // Host header containing an IP address or unusual port
            if (preg_match('/:\d{5,}/', $hostHeader) ||
                preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/', $hostHeader)) {
                $findings[] = 'Host header with IP or unusual port in password reset';
                $maxScore = max($maxScore, 60);
            }
        }

        // X-Forwarded-Host injection (commonly used for Host header injection)
        $xForwardedHost = $request->getHeader('X-Forwarded-Host');
        if ($xForwardedHost !== null && $xForwardedHost !== '') {
            $findings[] = sprintf('X-Forwarded-Host present in password reset: %s', substr($xForwardedHost, 0, 80));
            $maxScore = max($maxScore, 65);
        }

        // Multiple password reset indicators
        if (count($findings) >= 3) {
            $maxScore = max($maxScore, 70);
        }

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'Password reset abuse detected: %s',
            implode('; ', array_slice($findings, 0, 3))
        );

        return new DetectionResult([18, 15], $comment, $maxScore, $this->getName());
    }

    /**
     * Extract the username from POST data by checking multiple possible field names.
     *
     * @param array<string, mixed> $postData
     */
    private function extractUsername(array $postData): ?string
    {
        foreach (self::USERNAME_FIELDS as $field) {
            if (isset($postData[$field]) && is_string($postData[$field]) && $postData[$field] !== '') {
                return $postData[$field];
            }
        }
        return null;
    }
}
