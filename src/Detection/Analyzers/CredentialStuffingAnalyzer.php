<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;
use ReportedIp\Honeypot\Detection\PatternLibrary;

/**
 * Detects credential stuffing patterns.
 *
 * Checks POST data for common username/password lists, JSON credential payloads,
 * Authorization headers with default credentials, and default password patterns.
 */
final class CredentialStuffingAnalyzer implements AnalyzerInterface
{
    /** Form fields commonly used for usernames. */
    private const USERNAME_FIELDS = [
        'log', 'username', 'user', 'user_login', 'email', 'login',
        'name', 'usr', 'account', 'userid', 'user_id',
    ];

    /** Form fields commonly used for passwords. */
    private const PASSWORD_FIELDS = [
        'pwd', 'password', 'pass', 'user_pass', 'passwd',
        'user_password', 'secret', 'passw', 'pass_word',
    ];

    public function getName(): string
    {
        return 'CredentialStuffing';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        if (!$request->isPost()) {
            // Also check Authorization header on any request
            return $this->checkAuthorizationHeader($request);
        }

        $findings = [];
        $maxScore = 0;

        $postData = $request->getPostData();
        $body = $request->getBody();

        // Check regular form POST data for credential fields
        $this->checkFormCredentials($postData, $findings, $maxScore);

        // Check JSON body for credential patterns
        $contentType = $request->getContentType();
        if ($contentType !== null && str_contains(strtolower($contentType), 'json') && $body !== '') {
            $this->checkJsonCredentials($body, $findings, $maxScore);
        }

        // Check Authorization header
        $authResult = $this->checkAuthorizationHeader($request);
        if ($authResult !== null) {
            $findings[] = $authResult->getComment();
            $maxScore = max($maxScore, $authResult->getScore());
        }

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'Credential stuffing detected: %s',
            implode('; ', array_slice($findings, 0, 3))
        );

        return new DetectionResult([18, 15], $comment, $maxScore, $this->getName());
    }

    /**
     * @param array<string, mixed> $postData
     */
    private function checkFormCredentials(array $postData, array &$findings, int &$maxScore): void
    {
        $commonUsernames = PatternLibrary::commonUsernames();
        $commonPasswords = PatternLibrary::commonPasswords();

        $detectedUsername = null;
        $detectedPassword = null;

        // Extract username
        foreach (self::USERNAME_FIELDS as $field) {
            if (isset($postData[$field]) && is_string($postData[$field]) && $postData[$field] !== '') {
                $detectedUsername = $postData[$field];
                break;
            }
        }

        // Extract password
        foreach (self::PASSWORD_FIELDS as $field) {
            if (isset($postData[$field]) && is_string($postData[$field]) && $postData[$field] !== '') {
                $detectedPassword = $postData[$field];
                break;
            }
        }

        if ($detectedUsername !== null && $detectedPassword !== null) {
            $isCommonUsername = in_array(strtolower($detectedUsername), $commonUsernames, true);
            $isCommonPassword = in_array($detectedPassword, $commonPasswords, true);

            if ($isCommonUsername && $isCommonPassword) {
                $findings[] = sprintf(
                    'Default credential pair: %s with common password',
                    $detectedUsername
                );
                $maxScore = max($maxScore, 90);
            } elseif ($isCommonUsername) {
                $findings[] = sprintf('Common username in credential attempt: %s', $detectedUsername);
                $maxScore = max($maxScore, 75);
            } elseif ($isCommonPassword) {
                $findings[] = 'Common/default password in credential attempt';
                $maxScore = max($maxScore, 70);
            } else {
                $findings[] = 'Credential submission detected';
                $maxScore = max($maxScore, 65);
            }
        } elseif ($detectedUsername !== null) {
            $isCommonUsername = in_array(strtolower($detectedUsername), $commonUsernames, true);
            if ($isCommonUsername) {
                $findings[] = sprintf('Common username submitted: %s', $detectedUsername);
                $maxScore = max($maxScore, 65);
            }
        }
    }

    private function checkJsonCredentials(string $body, array &$findings, int &$maxScore): void
    {
        $data = @json_decode($body, true);
        if (!is_array($data)) {
            return;
        }

        $commonUsernames = PatternLibrary::commonUsernames();
        $commonPasswords = PatternLibrary::commonPasswords();

        // Check for username/password keys in JSON
        $usernameKeys = ['username', 'user', 'login', 'email', 'account'];
        $passwordKeys = ['password', 'pass', 'passwd', 'secret', 'pwd'];

        $jsonUsername = null;
        $jsonPassword = null;

        foreach ($usernameKeys as $key) {
            if (isset($data[$key]) && is_string($data[$key])) {
                $jsonUsername = $data[$key];
                break;
            }
        }

        foreach ($passwordKeys as $key) {
            if (isset($data[$key]) && is_string($data[$key])) {
                $jsonPassword = $data[$key];
                break;
            }
        }

        if ($jsonUsername !== null && $jsonPassword !== null) {
            $isCommonUser = in_array(strtolower($jsonUsername), $commonUsernames, true);
            $isCommonPass = in_array($jsonPassword, $commonPasswords, true);

            if ($isCommonUser && $isCommonPass) {
                $findings[] = sprintf('JSON credential stuffing: default pair %s', $jsonUsername);
                $maxScore = max($maxScore, 90);
            } elseif ($isCommonUser || $isCommonPass) {
                $findings[] = 'JSON credential attempt with common credentials';
                $maxScore = max($maxScore, 75);
            } else {
                $findings[] = 'JSON credential submission detected';
                $maxScore = max($maxScore, 65);
            }
        }
    }

    private function checkAuthorizationHeader(Request $request): ?DetectionResult
    {
        $authHeader = $request->getHeader('Authorization');
        if ($authHeader === null || $authHeader === '') {
            return null;
        }

        $findings = [];
        $maxScore = 0;

        // Check Basic auth
        if (preg_match('/^Basic\s+(.+)$/i', $authHeader, $matches)) {
            $decoded = @base64_decode($matches[1], true);
            if ($decoded !== false && str_contains($decoded, ':')) {
                [$user, $pass] = explode(':', $decoded, 2);

                $commonUsernames = PatternLibrary::commonUsernames();
                $commonPasswords = PatternLibrary::commonPasswords();

                $isCommonUser = in_array(strtolower($user), $commonUsernames, true);
                $isCommonPass = in_array($pass, $commonPasswords, true);

                if ($isCommonUser && $isCommonPass) {
                    $findings[] = sprintf('Basic auth with default credentials: %s', $user);
                    $maxScore = 90;
                } elseif ($isCommonUser) {
                    $findings[] = sprintf('Basic auth with common username: %s', $user);
                    $maxScore = 75;
                } else {
                    $findings[] = 'Basic auth credential attempt';
                    $maxScore = 65;
                }
            }
        }

        // Check Bearer token (unusual patterns)
        if (preg_match('/^Bearer\s+(.+)$/i', $authHeader, $matches)) {
            $token = $matches[1];
            // Very short tokens are suspicious (likely testing/probing)
            if (mb_strlen($token) < 10) {
                $findings[] = 'Suspicious Bearer token (too short)';
                $maxScore = max($maxScore, 50);
            }
        }

        if (empty($findings)) {
            return null;
        }

        $comment = implode('; ', $findings);
        return new DetectionResult([18, 15], $comment, $maxScore, $this->getName());
    }
}
