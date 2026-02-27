<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;
use ReportedIp\Honeypot\Detection\PatternLibrary;

/**
 * Score-based spam detection on POST form data.
 *
 * Checks for spam keywords, excessive URLs, HTML/BBCode in non-HTML fields,
 * filled honeypot fields, and other form spam indicators.
 */
final class FormSpamAnalyzer implements AnalyzerInterface
{
    private const URL_PATTERN = '/https?:\/\/[^\s<>"\']+/i';
    private const MAX_URLS_ALLOWED = 2;
    private const MAX_FIELD_LENGTH = 5000;

    public function getName(): string
    {
        return 'FormSpam';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        // Only analyze POST requests with form data
        if (!$request->isPost()) {
            return null;
        }

        $postData = $request->getPostData();
        if (empty($postData)) {
            return null;
        }

        $spamScore = 0;
        $findings = [];

        // Check for filled honeypot fields (common trap field names)
        $honeypotFields = ['honeypot', 'hp_field', 'url_verify', 'website_url', 'fax_number', 'middle_name_2'];
        foreach ($honeypotFields as $field) {
            if (isset($postData[$field]) && $postData[$field] !== '') {
                $findings[] = sprintf('Honeypot field "%s" was filled', $field);
                $spamScore += 40;
            }
        }

        // Check for timing-based honeypot (submitted too quickly)
        if (isset($postData['_form_time']) && is_numeric($postData['_form_time'])) {
            $formTime = (int) $postData['_form_time'];
            $timeDiff = time() - $formTime;
            if ($timeDiff < 3 && $timeDiff >= 0) {
                $findings[] = sprintf('Form submitted too quickly (%d seconds)', $timeDiff);
                $spamScore += 30;
            }
        }

        // Analyze all text fields
        $combinedText = '';
        foreach ($postData as $key => $value) {
            if (!is_string($value) || $value === '') {
                continue;
            }

            $combinedText .= ' ' . $value;

            // Check for excessively long field values
            if (mb_strlen($value) > self::MAX_FIELD_LENGTH) {
                $findings[] = sprintf('Excessively long form field "%s" (%d chars)', $key, mb_strlen($value));
                $spamScore += 15;
            }

            // Check for HTML/BBCode in non-HTML fields
            if ($key !== 'content' && $key !== 'body' && $key !== 'message' && $key !== 'description') {
                if (preg_match('/<\s*(a\s+href|img\s|script|iframe|div|span|style)\s*/i', $value)) {
                    $findings[] = sprintf('HTML injection in field "%s"', $key);
                    $spamScore += 20;
                }
                if (preg_match('/\[url=|\[img\]|\[b\]|\[i\]|\[color=/i', $value)) {
                    $findings[] = sprintf('BBCode in field "%s"', $key);
                    $spamScore += 15;
                }
            }
        }

        if ($combinedText === '') {
            return null;
        }

        // Check for spam keywords
        $spamPatterns = PatternLibrary::spamKeywords();
        $keywordMatches = 0;
        foreach ($spamPatterns as $pattern) {
            if (preg_match($pattern, $combinedText)) {
                $keywordMatches++;
            }
        }

        if ($keywordMatches >= 3) {
            $findings[] = sprintf('Multiple spam keywords detected (%d matches)', $keywordMatches);
            $spamScore += 30;
        } elseif ($keywordMatches >= 1) {
            $findings[] = sprintf('Spam keywords detected (%d matches)', $keywordMatches);
            $spamScore += 15;
        }

        // Check for excessive URLs
        preg_match_all(self::URL_PATTERN, $combinedText, $urlMatches);
        $urlCount = count($urlMatches[0] ?? []);
        if ($urlCount > self::MAX_URLS_ALLOWED) {
            $findings[] = sprintf('Excessive URLs in form data (%d URLs)', $urlCount);
            $spamScore += min(30, ($urlCount - self::MAX_URLS_ALLOWED) * 10);
        }

        // Check email format in email fields
        $emailFields = ['email', 'mail', 'e-mail', 'email_address', 'contact_email'];
        foreach ($emailFields as $field) {
            if (isset($postData[$field]) && is_string($postData[$field]) && $postData[$field] !== '') {
                if (!filter_var($postData[$field], FILTER_VALIDATE_EMAIL)) {
                    $findings[] = sprintf('Invalid email format in field "%s"', $field);
                    $spamScore += 15;
                }
            }
        }

        // Check for high non-ASCII ratio in typically Latin fields
        $nameFields = ['name', 'first_name', 'last_name', 'author'];
        foreach ($nameFields as $field) {
            if (isset($postData[$field]) && is_string($postData[$field]) && mb_strlen($postData[$field]) > 3) {
                $ratio = $this->nonAsciiRatio($postData[$field]);
                if ($ratio > 0.7) {
                    $findings[] = sprintf('High non-ASCII ratio in field "%s" (%.0f%%)', $field, $ratio * 100);
                    $spamScore += 10;
                }
            }
        }

        // Cap score at 80
        $spamScore = min(80, $spamScore);

        // Minimum threshold to report
        if ($spamScore < 30) {
            return null;
        }

        $comment = sprintf(
            'Form spam detected (score: %d): %s',
            $spamScore,
            implode('; ', array_slice($findings, 0, 3))
        );

        return new DetectionResult([40, 12, 10], $comment, $spamScore, $this->getName());
    }

    /**
     * Calculate the ratio of non-ASCII characters in a string.
     */
    private function nonAsciiRatio(string $text): float
    {
        $total = mb_strlen($text);
        if ($total === 0) {
            return 0.0;
        }

        $asciiCount = 0;
        for ($i = 0; $i < $total; $i++) {
            $char = mb_substr($text, $i, 1);
            if (ord($char) < 128) {
                $asciiCount++;
            }
        }

        return 1.0 - ($asciiCount / $total);
    }
}
