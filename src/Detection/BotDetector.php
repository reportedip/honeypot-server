<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection;

/**
 * Centralized bot detection and classification.
 */
final class BotDetector
{
    /** @var string[] */
    private const LEGITIMATE_BOTS = [
        'Googlebot',
        'Bingbot',
        'Slurp',
        'DuckDuckBot',
        'Baiduspider',
        'YandexBot',
        'Sogou',
        'MojeekBot',
        'SeznamBot',
        'Qwantify',
        'archive.org_bot',
        'ia_archiver',
        'facebookexternalhit',
        'Twitterbot',
        'LinkedInBot',
        'Pinterestbot',
        'Slackbot',
        'Discordbot',
        'TelegramBot',
        'WhatsApp',
        'Applebot',
        'PingdomBot',
        'UptimeRobot',
        'AdsBot-Google',
        'Mediapartners-Google',
        'GoogleOther',
        'Google-InspectionTool',
        'Storebot-Google',
        'Google-Read-Aloud',
        'Google-Site-Verification',
        'BingPreview',
        'msnbot',
        'AhrefsBot',
        'SemrushBot',
    ];

    /** @var array<string, string> */
    private const AI_AGENTS = [
        'GPTBot'                => 'GPTBot (OpenAI)',
        'ChatGPT-User'          => 'ChatGPT',
        'OAI-SearchBot'         => 'OpenAI SearchBot',
        'ClaudeBot'             => 'Claude (Anthropic)',
        'Claude-User'           => 'Claude User',
        'Claude-SearchBot'      => 'Claude SearchBot',
        'Claude-Web'            => 'Claude Web',
        'Anthropic'             => 'Anthropic',
        'PerplexityBot'         => 'Perplexity',
        'Perplexity-User'       => 'Perplexity User',
        'Google-Extended'       => 'Google AI (Gemini)',
        'Googlebot-Extended'    => 'Google AI Training',
        'Google-CloudVertexBot' => 'Google Cloud Vertex AI',
        'Applebot-Extended'     => 'Apple AI Training',
        'Amazonbot'             => 'Amazon AI / Alexa',
        'Amzn-SearchBot'        => 'Amazon SearchBot',
        'Amzn-User'             => 'Amazon User',
        'Meta-ExternalAgent'    => 'Meta AI',
        'Meta-ExternalFetcher'  => 'Meta External Fetcher',
        'FacebookBot'           => 'Facebook AI',
        'MistralBot'            => 'Mistral AI',
        'DeepSeek'              => 'DeepSeek AI',
        'Bytespider'            => 'ByteDance (TikTok AI)',
        'Diffbot'               => 'Diffbot',
        'Cohere-ai'             => 'Cohere AI',
        'YouBot'                => 'You.com AI',
        'DuckAssistBot'         => 'DuckDuckGo AI',
        'Timpibot'              => 'Timpi AI',
        'CCBot'                 => 'Common Crawl (AI Training)',
        'ImagesiftBot'          => 'Imagesift AI',
        'Omgilibot'             => 'Omgili AI',
    ];

    /** @var array<string, string> */
    private const BAD_BOT_PATTERNS = [
        '/^curl\//i'             => 'curl',
        '/^wget\//i'             => 'wget',
        '/^python-requests\//i'  => 'python-requests',
        '/^python-urllib/i'      => 'python-urllib',
        '/^aiohttp\//i'          => 'aiohttp',
        '/^httpx\//i'            => 'httpx',
        '/^Go-http-client/i'     => 'Go-http-client',
        '/^Java\//i'             => 'Java HTTP',
        '/^PHP\//i'              => 'PHP HTTP',
        '/^Ruby/i'               => 'Ruby HTTP',
        '/^reqwest\//i'          => 'reqwest',
        '/^axios\//i'            => 'axios',
        '/^node-fetch/i'         => 'node-fetch',
        '/^okhttp/i'             => 'OkHttp',
        '/^libwww-perl/i'        => 'libwww-perl',
        '/^lwp-/i'               => 'LWP',
        '/^Mechanize/i'          => 'Mechanize',
        '/^Scrapy/i'             => 'Scrapy',
        '/^PostmanRuntime\//i'   => 'Postman',
        '/^GuzzleHttp\//i'       => 'Guzzle',
    ];

    /**
     * Check if the user agent belongs to a legitimate search engine bot.
     */
    public static function isLegitimateBot(string $userAgent): bool
    {
        foreach (self::LEGITIMATE_BOTS as $botName) {
            if (stripos($userAgent, $botName) !== false) {
                return true;
            }
        }
        foreach (self::AI_AGENTS as $pattern => $name) {
            if (stripos($userAgent, $pattern) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * Classify a user agent into a visitor type.
     *
     * @return array{type: string, name: string}
     */
    public static function classify(string $userAgent): array
    {
        if ($userAgent === '') {
            return ['type' => 'bad_bot', 'name' => 'Empty UA'];
        }

        // Check AI agents first (before legitimate bots, since some overlap)
        foreach (self::AI_AGENTS as $pattern => $name) {
            if (stripos($userAgent, $pattern) !== false) {
                return ['type' => 'ai_agent', 'name' => $name];
            }
        }

        // Check legitimate bots
        foreach (self::LEGITIMATE_BOTS as $botName) {
            if (stripos($userAgent, $botName) !== false) {
                return ['type' => 'good_bot', 'name' => $botName];
            }
        }

        // Check scanning tools from PatternLibrary
        foreach (PatternLibrary::suspiciousUserAgents() as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                $name = self::extractToolName($pattern);
                return ['type' => 'bad_bot', 'name' => $name];
            }
        }

        // Check automated HTTP clients
        foreach (self::BAD_BOT_PATTERNS as $pattern => $name) {
            if (preg_match($pattern, $userAgent)) {
                return ['type' => 'bad_bot', 'name' => $name];
            }
        }

        // Generic bot indicator
        if (preg_match('/\b(bot|crawler|spider|scan|scrape|harvest|extract)\b/i', $userAgent)) {
            return ['type' => 'bad_bot', 'name' => 'Unknown Bot'];
        }

        return ['type' => 'human', 'name' => ''];
    }

    private static function extractToolName(string $pattern): string
    {
        if (preg_match('/\/(\w+)/i', $pattern, $m)) {
            return $m[1];
        }
        return trim($pattern, '/i');
    }
}
