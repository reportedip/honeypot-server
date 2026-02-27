<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\BotDetector;
use ReportedIp\Honeypot\Detection\DetectionResult;
use ReportedIp\Honeypot\Detection\PatternLibrary;

/**
 * Detects suspicious User-Agent strings.
 *
 * Identifies known scanning tools, generic bots, empty User-Agents,
 * very old browser versions, and automated HTTP client libraries.
 */
final class UserAgentAnalyzer implements AnalyzerInterface
{
    /** Legitimate bots that should not trigger generic bot detection. */
    private const LEGITIMATE_BOTS = [
        'Googlebot',
        'Bingbot',
        'Slurp',
        'DuckDuckBot',
        'Baiduspider',
        'YandexBot',
        'facebookexternalhit',
        'Twitterbot',
        'LinkedInBot',
        'Applebot',
        'PingdomBot',
        'UptimeRobot',
    ];

    public function getName(): string
    {
        return 'UserAgent';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $ua = $request->getUserAgent();
        $findings = [];
        $maxScore = 0;

        // Empty User-Agent
        if ($ua === '') {
            $findings[] = 'Empty User-Agent header';
            $maxScore = max($maxScore, 30);
        }

        if ($ua === '') {
            if (empty($findings)) {
                return null;
            }

            return new DetectionResult(
                [19, 49],
                'Suspicious User-Agent: ' . implode('; ', $findings),
                $maxScore,
                $this->getName()
            );
        }

        // Check known scanning tools
        foreach (PatternLibrary::suspiciousUserAgents() as $pattern) {
            if (preg_match($pattern, $ua)) {
                $tool = $this->extractToolName($pattern);
                $findings[] = sprintf('Known scanning tool detected: %s', $tool);
                $maxScore = max($maxScore, 80);
                break; // One tool match is sufficient
            }
        }

        // Check for automated HTTP client libraries
        $automatedPatterns = [
            '/^curl\//i' => ['curl', 50],
            '/^wget\//i' => ['wget', 50],
            '/^python-requests\//i' => ['python-requests', 45],
            '/^python-urllib/i' => ['python-urllib', 50],
            '/^Go-http-client/i' => ['Go-http-client', 45],
            '/^Java\//i' => ['Java HTTP client', 45],
            '/^PHP\//i' => ['PHP HTTP client', 50],
            '/^Ruby/i' => ['Ruby HTTP client', 40],
            '/^axios\//i' => ['axios', 40],
            '/^node-fetch/i' => ['node-fetch', 40],
            '/^okhttp/i' => ['OkHttp', 40],
            '/^libwww-perl/i' => ['libwww-perl', 55],
            '/^lwp-/i' => ['LWP', 50],
            '/^Wget/i' => ['Wget', 50],
            '/^Mechanize/i' => ['Mechanize', 55],
            '/^Scrapy/i' => ['Scrapy', 60],
        ];

        foreach ($automatedPatterns as $pattern => [$name, $score]) {
            if (preg_match($pattern, $ua)) {
                $findings[] = sprintf('Automated HTTP client: %s', $name);
                $maxScore = max($maxScore, $score);
                break;
            }
        }

        // Check for very old browser versions (likely spoofed or abandoned)
        $oldBrowserPatterns = [
            '/MSIE\s*[1-7]\./i' => 'Internet Explorer 7 or older',
            '/Chrome\/[1-3]\d\./i' => 'Chrome version below 40',
            '/Firefox\/[1-3]\d\./i' => 'Firefox version below 40',
        ];

        foreach ($oldBrowserPatterns as $pattern => $description) {
            if (preg_match($pattern, $ua)) {
                $findings[] = sprintf('Very old browser: %s', $description);
                $maxScore = max($maxScore, 35);
                break;
            }
        }

        // Check for generic bot indicators (but not legitimate bots)
        if ($this->hasGenericBotIndicator($ua) && !$this->isLegitimateBot($ua)) {
            $findings[] = 'Generic bot/crawler/scanner indicator in User-Agent';
            $maxScore = max($maxScore, 40);
        }

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'Suspicious User-Agent detected: %s',
            implode('; ', array_slice($findings, 0, 3))
        );

        return new DetectionResult([19, 49], $comment, $maxScore, $this->getName());
    }

    private function hasGenericBotIndicator(string $ua): bool
    {
        return (bool) preg_match('/\b(bot|crawler|spider|scan|scrape|harvest|extract)\b/i', $ua);
    }

    private function isLegitimateBot(string $ua): bool
    {
        return BotDetector::isLegitimateBot($ua);
    }

    private function extractToolName(string $pattern): string
    {
        // Extract the main keyword from the pattern
        if (preg_match('/\/(\w+)/i', $pattern, $m)) {
            return $m[1];
        }
        // Fallback: clean pattern delimiters
        return trim($pattern, '/i');
    }
}
