<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;

/**
 * Detects automated registration attempts and registration spam.
 *
 * Checks for POST requests to CMS registration endpoints, disposable email domains,
 * spam keywords in form fields, suspiciously fast submissions, and common bot
 * registration patterns.
 */
final class RegistrationHoneypotAnalyzer implements AnalyzerInterface
{
    /** Known CMS registration endpoint patterns. */
    private const REGISTRATION_PATHS = [
        '/\/wp-login\.php\?action=register/i',
        '/\/wp-signup\.php/i',
        '/\/user\/register/i',
        '/\/index\.php\?option=com_users&view=registration/i',
        '/\/index\.php\?option=com_users&task=registration/i',
        '/\/component\/users\/\?view=registration/i',
        '/\/register\/?$/i',
        '/\/signup\/?$/i',
        '/\/create[_\-]?account/i',
        '/\/join\/?$/i',
    ];

    /** Disposable email provider domains. */
    private const DISPOSABLE_DOMAINS = [
        'tempmail',
        '10minutemail',
        'guerrillamail',
        'mailinator',
        'throwaway',
        'yopmail',
        'sharklasers',
        'guerrillamailblock',
        'grr.la',
        'dispostable',
        'tempail',
        'fakeinbox',
        'trashmail',
        'getnada',
        'maildrop',
        'temp-mail',
        'emailondeck',
        'mohmal',
    ];

    /** Fields commonly used in registration forms. */
    private const USERNAME_FIELDS = ['user_login', 'username', 'user', 'login', 'nickname', 'name'];
    private const EMAIL_FIELDS = ['user_email', 'email', 'mail', 'e-mail', 'email_address'];

    public function getName(): string
    {
        return 'RegistrationHoneypot';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        if (!$request->isPost()) {
            return null;
        }

        $path = $request->getPath();
        $uri = $request->getUri();

        // Check if this targets a registration endpoint
        $isRegistration = false;
        foreach (self::REGISTRATION_PATHS as $pattern) {
            if (preg_match($pattern, $uri) || preg_match($pattern, $path)) {
                $isRegistration = true;
                break;
            }
        }

        if (!$isRegistration) {
            return null;
        }

        $postData = $request->getPostData();
        $findings = [];
        $maxScore = 0;

        // Any POST to a registration endpoint in a honeypot is suspicious
        $findings[] = sprintf('Registration attempt: %s', $path);
        $maxScore = max($maxScore, 50);

        // Check for disposable email domains
        $email = $this->extractField($postData, self::EMAIL_FIELDS);
        if ($email !== null) {
            $emailLower = strtolower($email);
            foreach (self::DISPOSABLE_DOMAINS as $domain) {
                if (str_contains($emailLower, $domain)) {
                    $findings[] = sprintf('Disposable email domain: %s', $domain);
                    $maxScore = max($maxScore, 70);
                    break;
                }
            }

            // Check for invalid email format
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $findings[] = 'Invalid email format in registration';
                $maxScore = max($maxScore, 60);
            }
        }

        // Check for spam keywords in username/email
        $username = $this->extractField($postData, self::USERNAME_FIELDS);
        $combinedText = ($username ?? '') . ' ' . ($email ?? '');

        $spamPatterns = [
            '/\b(admin|test|root|guest)\d{2,}/i',
            '/^[a-z]{1,3}\d{5,}$/i',
            '/\b(buy|sell|cheap|free|click)\b/i',
            '/\b(viagra|cialis|casino|poker|lottery)\b/i',
            '/[a-z]{20,}/i',
        ];

        foreach ($spamPatterns as $pattern) {
            if (preg_match($pattern, $combinedText)) {
                $findings[] = 'Spam pattern in registration fields';
                $maxScore = max($maxScore, 65);
                break;
            }
        }

        // Check for very fast form submission (timing-based honeypot)
        $timingFields = ['_form_time', 'form_timestamp', 'registration_time', 'timestamp'];
        foreach ($timingFields as $field) {
            if (isset($postData[$field]) && is_numeric($postData[$field])) {
                $formTime = (int) $postData[$field];
                $timeDiff = time() - $formTime;
                if ($timeDiff < 5 && $timeDiff >= 0) {
                    $findings[] = sprintf('Registration submitted too quickly (%d seconds)', $timeDiff);
                    $maxScore = max($maxScore, 70);
                }
                break;
            }
        }

        // Check for common bot registration patterns
        if ($username !== null && $email !== null) {
            // Username and email are identical (minus domain)
            $emailLocal = explode('@', $email)[0] ?? '';
            if ($username !== '' && $emailLocal !== '' && strtolower($username) === strtolower($emailLocal)) {
                // Not inherently suspicious by itself, but adds to score
                $maxScore = max($maxScore, 55);
            }

            // All fields filled with gibberish-like random strings
            if (preg_match('/^[a-z0-9]{15,}$/i', $username)) {
                $findings[] = 'Random-looking username pattern';
                $maxScore = max($maxScore, 65);
            }
        }

        // Check for multiple registration-related POST fields being empty (bot framework)
        $emptyRequiredFields = 0;
        $allRegFields = array_merge(self::USERNAME_FIELDS, self::EMAIL_FIELDS);
        $hasAnyField = false;
        foreach ($allRegFields as $field) {
            if (isset($postData[$field])) {
                $hasAnyField = true;
                if ($postData[$field] === '') {
                    $emptyRequiredFields++;
                }
            }
        }

        if ($hasAnyField && $emptyRequiredFields >= 2) {
            $findings[] = sprintf('Multiple empty registration fields (%d empty)', $emptyRequiredFields);
            $maxScore = max($maxScore, 60);
        }

        if (empty($findings)) {
            return null;
        }

        // Cap score at 75
        $maxScore = min(75, $maxScore);

        $comment = sprintf(
            'Registration spam detected: %s',
            implode('; ', array_slice(array_unique($findings), 0, 3))
        );

        return new DetectionResult([41, 15], $comment, $maxScore, $this->getName());
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
}
