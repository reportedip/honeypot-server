<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;

/**
 * Detects Unicode and encoding-based attack techniques.
 *
 * Checks for overlong UTF-8 encoding, fullwidth character bypass,
 * Unicode normalization attacks (RTL override, zero-width space),
 * BOM injection, null byte variants, and mixed encoding bypass attempts.
 */
final class UnicodeEncodingAttackAnalyzer implements AnalyzerInterface
{
    /** Overlong UTF-8 encoding patterns (used to bypass security filters). */
    private const OVERLONG_PATTERNS = [
        '/%c0%af/i',           // Overlong encoding of /
        '/%c0%ae/i',           // Overlong encoding of .
        '/%c1%9c/i',           // Overlong encoding of \
        '/%c0%2f/i',           // Overlong variant of /
        '/%c0%5c/i',           // Overlong variant of \
        '/%c0%a0/i',           // Overlong space
        '/%e0%80%af/i',        // Three-byte overlong /
        '/%e0%80%ae/i',        // Three-byte overlong .
        '/%f0%80%80%af/i',     // Four-byte overlong /
    ];

    /** Fullwidth Unicode characters used for filter bypass. */
    private const FULLWIDTH_PATTERNS = [
        '/%ef%bc%8e/i',        // Fullwidth . (U+FF0E)
        '/%ef%bc%8f/i',        // Fullwidth / (U+FF0F)
        '/%ef%bc%bc/i',        // Fullwidth \ (U+FF3C)
        '/%ef%bc%9a/i',        // Fullwidth : (U+FF1A)
        '/%ef%bc%9c/i',        // Fullwidth < (U+FF1C)
        '/%ef%bc%9e/i',        // Fullwidth > (U+FF1E)
    ];

    /** Unicode control/manipulation characters. */
    private const UNICODE_CONTROL_PATTERNS = [
        '/%e2%80%ae/i',        // RTL override (U+202E)
        '/%e2%80%ad/i',        // LTR override (U+202D)
        '/%e2%80%8b/i',        // Zero-width space (U+200B)
        '/%e2%80%8c/i',        // Zero-width non-joiner (U+200C)
        '/%e2%80%8d/i',        // Zero-width joiner (U+200D)
        '/%e2%80%8f/i',        // RTL mark (U+200F)
        '/%e2%80%8e/i',        // LTR mark (U+200E)
        '/%e2%80%aa/i',        // LTR embedding (U+202A)
        '/%e2%80%ab/i',        // RTL embedding (U+202B)
        '/%e2%81%a0/i',        // Word joiner (U+2060)
        '/%ef%bb%bf/i',        // BOM (U+FEFF)
    ];

    /** Null byte encoding variants. */
    private const NULL_BYTE_PATTERNS = [
        '/%00/',               // Standard null byte
        '/%u0000/i',           // Unicode null byte
        '/%25%30%30/i',        // Double-encoded null byte
        '/\\\\x00/',           // Escaped null byte
        '/\\\\0/',             // Escaped zero
    ];

    public function getName(): string
    {
        return 'UnicodeEncodingAttack';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $findings = [];
        $maxScore = 0;

        // Collect all targets to check (raw URI, path, query params, POST data, body)
        $targets = $this->collectTargets($request);

        foreach ($targets as $label => $value) {
            if ($value === '' || mb_strlen($value) < 3) {
                continue;
            }

            // Check for overlong UTF-8 encoding
            foreach (self::OVERLONG_PATTERNS as $pattern) {
                if (preg_match($pattern, $value)) {
                    $findings[] = sprintf('Overlong UTF-8 encoding in %s', $label);
                    $maxScore = max($maxScore, 70);
                    break;
                }
            }

            // Check for fullwidth character bypass
            foreach (self::FULLWIDTH_PATTERNS as $pattern) {
                if (preg_match($pattern, $value)) {
                    $findings[] = sprintf('Fullwidth Unicode character bypass in %s', $label);
                    $maxScore = max($maxScore, 65);
                    break;
                }
            }

            // Check for Unicode control characters
            foreach (self::UNICODE_CONTROL_PATTERNS as $pattern) {
                if (preg_match($pattern, $value)) {
                    $findings[] = sprintf('Unicode control character injection in %s', $label);
                    $maxScore = max($maxScore, 60);
                    break;
                }
            }

            // Check for null bytes in various encodings
            foreach (self::NULL_BYTE_PATTERNS as $pattern) {
                if (preg_match($pattern, $value)) {
                    $findings[] = sprintf('Null byte injection in %s', $label);
                    $maxScore = max($maxScore, 70);
                    break;
                }
            }

            // Check for mixed encoding suggesting bypass attempts
            if ($this->hasMixedEncoding($value)) {
                $findings[] = sprintf('Mixed encoding bypass attempt in %s', $label);
                $maxScore = max($maxScore, 55);
            }
        }

        // Check raw URI for BOM injection specifically
        $rawUri = $request->getUri();
        if (preg_match('/%ef%bb%bf/i', $rawUri)) {
            $findings[] = 'Byte Order Mark (BOM) injection in URI';
            $maxScore = max($maxScore, 60);
        }

        // Check for IRI/Unicode in hostname parts via Host header
        $host = $request->getHeader('Host');
        if ($host !== null && $host !== '') {
            if (preg_match('/[^\x20-\x7E]/', $host) ||
                preg_match('/%[cC][0-9a-fA-F]%[0-9a-fA-F]{2}/', $host) ||
                preg_match('/xn--/i', $host)) {
                $findings[] = sprintf('IRI/Unicode in hostname: %s', substr($host, 0, 80));
                $maxScore = max($maxScore, 60);
            }
        }

        // Multiple encoding attack indicators increase severity
        if (count($findings) >= 3) {
            $maxScore = max($maxScore, 75);
        }

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'Unicode/encoding attack detected: %s',
            implode('; ', array_slice($findings, 0, 3))
        );

        return new DetectionResult([15, 45], $comment, $maxScore, $this->getName());
    }

    /**
     * Collect all string targets to analyze from the request.
     *
     * @return array<string, string>
     */
    private function collectTargets(Request $request): array
    {
        $targets = [];

        $targets['URI'] = $request->getUri();
        $targets['path'] = $request->getPath();

        foreach ($request->getQueryParams() as $key => $val) {
            $targets["query param '{$key}'"] = is_string($val) ? $val : (string) $val;
            // Also check parameter names
            $targets["query key '{$key}'"] = $key;
        }

        foreach ($request->getPostData() as $key => $val) {
            $targets["POST field '{$key}'"] = is_string($val) ? $val : (string) $val;
        }

        $body = $request->getBody();
        if ($body !== '') {
            $targets['request body'] = $body;
        }

        return $targets;
    }

    /**
     * Detect mixed encoding patterns suggesting bypass attempts.
     *
     * Mixed encoding is when the same string uses multiple encoding schemes
     * (e.g., combining URL encoding, HTML entities, and raw characters).
     */
    private function hasMixedEncoding(string $value): bool
    {
        $encodingTypes = 0;

        // Standard URL encoding
        if (preg_match('/%[0-9a-fA-F]{2}/', $value)) {
            $encodingTypes++;
        }

        // Double URL encoding
        if (preg_match('/%25[0-9a-fA-F]{2}/', $value)) {
            $encodingTypes++;
        }

        // Unicode escape encoding (%uXXXX)
        if (preg_match('/%u[0-9a-fA-F]{4}/i', $value)) {
            $encodingTypes++;
        }

        // HTML entity encoding
        if (preg_match('/&#x?[0-9a-fA-F]+;/', $value)) {
            $encodingTypes++;
        }

        // Backslash Unicode encoding (\uXXXX)
        if (preg_match('/\\\\u[0-9a-fA-F]{4}/', $value)) {
            $encodingTypes++;
        }

        // At least 3 different encoding types in the same value is suspicious
        return $encodingTypes >= 3;
    }
}
