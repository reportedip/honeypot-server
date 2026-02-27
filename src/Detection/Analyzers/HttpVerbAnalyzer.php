<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;

/**
 * Detects unusual or dangerous HTTP methods.
 *
 * Flags non-standard verbs (TRACE, CONNECT, WebDAV methods, DEBUG),
 * excessively long method strings, and method override headers.
 */
final class HttpVerbAnalyzer implements AnalyzerInterface
{
    /** Standard safe methods that should not trigger detection. */
    private const SAFE_METHODS = ['GET', 'POST', 'HEAD', 'OPTIONS'];

    /** Methods that are suspicious in a typical web application context. */
    private const SUSPICIOUS_METHODS = [
        'TRACE'    => 60,
        'TRACK'    => 60,
        'DEBUG'    => 65,
        'CONNECT'  => 70,
        'PROPFIND' => 50,
        'PROPPATCH' => 55,
        'MKCOL'    => 55,
        'COPY'     => 50,
        'MOVE'     => 55,
        'LOCK'     => 50,
        'UNLOCK'   => 50,
        'PUT'      => 40,
        'DELETE'   => 45,
        'PATCH'    => 40,
        'SEARCH'   => 45,
        'PURGE'    => 50,
        'MKCALENDAR' => 55,
        'REPORT'   => 45,
    ];

    private const MAX_METHOD_LENGTH = 10;

    public function getName(): string
    {
        return 'HttpVerb';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $method = strtoupper($request->getMethod());
        $findings = [];
        $maxScore = 0;

        // Check for excessively long method (possible fuzzing)
        if (mb_strlen($method) > self::MAX_METHOD_LENGTH) {
            $findings[] = sprintf('Excessively long HTTP method (%d chars)', mb_strlen($method));
            $maxScore = max($maxScore, 65);
        }

        // Check for suspicious methods
        if (isset(self::SUSPICIOUS_METHODS[$method])) {
            $score = self::SUSPICIOUS_METHODS[$method];
            $findings[] = sprintf('Non-standard HTTP method: %s', $method);
            $maxScore = max($maxScore, $score);
        } elseif (!in_array($method, self::SAFE_METHODS, true) && mb_strlen($method) <= self::MAX_METHOD_LENGTH) {
            // Unknown method entirely
            $findings[] = sprintf('Unknown HTTP method: %s', $method);
            $maxScore = max($maxScore, 55);
        }

        // Check for method override headers
        $overrideHeaders = ['X-HTTP-Method-Override', 'X-Method-Override', 'X-HTTP-Method'];
        foreach ($overrideHeaders as $header) {
            $value = $request->getHeader($header);
            if ($value !== null && $value !== '') {
                $overrideMethod = strtoupper(trim($value));
                if (isset(self::SUSPICIOUS_METHODS[$overrideMethod])) {
                    $findings[] = sprintf(
                        'Method override via %s header to %s',
                        $header,
                        $overrideMethod
                    );
                    $maxScore = max($maxScore, self::SUSPICIOUS_METHODS[$overrideMethod]);
                }
            }
        }

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'Suspicious HTTP method detected: %s',
            implode('; ', $findings)
        );

        return new DetectionResult([21], $comment, $maxScore, $this->getName());
    }
}
