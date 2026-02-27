<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Content;

use ReportedIp\Honeypot\Core\Config;

/**
 * Generates content via OpenAI API (or compatible endpoint).
 */
final class ContentGenerator
{
    private Config $config;
    private float $lastCallTime = 0.0;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /**
     * Check if OpenAI API is configured.
     */
    public function isConfigured(): bool
    {
        return $this->config->get('openai_api_key', '') !== '';
    }

    /**
     * Generate a single content entry.
     *
     * @param string $language 'de' or 'en'
     * @return array<string, string>
     */
    public function generate(string $cmsProfile, string $topic = '', string $style = '', string $language = ''): array
    {
        if (!$this->isConfigured()) {
            throw new \RuntimeException('OpenAI API key is not configured.');
        }

        if ($language === '') {
            $language = $this->config->get('content_language', 'en');
        }

        $niche = $this->config->get('content_niche', '');
        $topicStr = $topic !== '' ? $topic : ($niche !== '' ? $niche : 'general business topics');
        $cmsLabel = ucfirst($cmsProfile);

        $langLabel = $language === 'de' ? 'Deutsch' : 'English';
        $langInstruction = $language === 'de'
            ? 'Schreibe den gesamten Content (Titel, Inhalt, Excerpt, Meta-Description, Kategorie) auf Deutsch. Der Slug muss trotzdem lowercase, ASCII-only und mit Bindestrichen sein.'
            : 'Write all content (title, content, excerpt, meta_description, category) in English.';

        $systemPrompt = $language === 'de'
            ? "Du bist Content-Writer für eine kleine Business-Website mit {$cmsLabel}. Generiere realistische Blog-Posts auf Deutsch. Antworte NUR mit JSON."
            : "You are a content writer for a small business website running {$cmsLabel}. Generate realistic blog posts in English. Reply ONLY with JSON.";

        $userPrompt = ($language === 'de' ? "Erstelle einen Blog-Post über: " : "Generate a blog post about: ") . "{$topicStr}.\n"
            . "CMS: {$cmsLabel}\n"
            . "Language: {$langLabel}\n"
            . "{$langInstruction}\n";
        if ($style !== '') {
            $userPrompt .= ($language === 'de' ? "Stil-Hinweise: " : "Style notes: ") . "{$style}\n";
        }
        $userPrompt .= "\nReturn JSON with these fields:\n"
            . "- title: string (catchy, SEO-friendly, in {$langLabel})\n"
            . "- slug: string (lowercase, ASCII-only, hyphenated, max 60 chars)\n"
            . "- content: string (HTML formatted, 3-5 paragraphs with <p> tags, ~300-500 words, in {$langLabel})\n"
            . "- excerpt: string (1-2 sentences summary, plain text, in {$langLabel})\n"
            . "- author: string (realistic name)\n"
            . "- category: string (one category, in {$langLabel})\n"
            . "- meta_description: string (max 160 chars, for SEO, in {$langLabel})";

        $response = $this->callApi($systemPrompt, $userPrompt);

        return $this->parseResponse($response, $cmsProfile);
    }

    /**
     * Generate multiple content entries.
     *
     * @param string $language 'de' or 'en'
     * @return array<int, array<string, string>>
     */
    public function generateBulk(string $cmsProfile, int $count, string $niche = '', string $language = ''): array
    {
        $results = [];
        $topics = $this->generateTopicVariations($niche !== '' ? $niche : ($this->config->get('content_niche', '') ?: 'business'), $count);

        for ($i = 0; $i < $count; $i++) {
            $result = $this->generate($cmsProfile, $topics[$i] ?? '', '', $language);
            // Assign a realistic published_date spread over 6-12 months
            $daysAgo = random_int(30, 365);
            $result['published_date'] = date('Y-m-d H:i:s', strtotime("-{$daysAgo} days"));
            $results[] = $result;
        }

        return $results;
    }

    /**
     * @return array<string, mixed>
     */
    private function callApi(string $systemPrompt, string $userPrompt): array
    {
        // Respect rate limit
        $now = microtime(true);
        $elapsed = $now - $this->lastCallTime;
        if ($elapsed < 2.0 && $this->lastCallTime > 0) {
            usleep((int) ((2.0 - $elapsed) * 1_000_000));
        }

        $apiKey = $this->config->get('openai_api_key', '');
        $baseUrl = rtrim($this->config->get('openai_base_url', 'https://api.openai.com/v1'), '/');
        $model = $this->config->get('openai_model', 'gpt-4o-mini');
        $caBundle = $this->config->get('ca_bundle', '');

        $payload = [
            'model'    => $model,
            'messages' => [
                ['role' => 'system', 'content' => $systemPrompt],
                ['role' => 'user', 'content' => $userPrompt],
            ],
            'response_format' => ['type' => 'json_object'],
            'temperature'     => 0.8,
            'max_tokens'      => 2000,
        ];

        $ch = curl_init();
        $curlOpts = [
            CURLOPT_URL            => $baseUrl . '/chat/completions',
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => json_encode($payload),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_HTTPHEADER     => [
                'Content-Type: application/json',
                'Authorization: Bearer ' . $apiKey,
            ],
        ];

        if ($caBundle !== '' && file_exists($caBundle)) {
            $curlOpts[CURLOPT_CAINFO] = $caBundle;
        }

        curl_setopt_array($ch, $curlOpts);
        $responseBody = curl_exec($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        $this->lastCallTime = microtime(true);

        if ($curlError !== '') {
            throw new \RuntimeException('OpenAI API connection error: ' . $curlError);
        }

        if ($httpCode !== 200) {
            $errorDetail = '';
            if (is_string($responseBody)) {
                $decoded = json_decode($responseBody, true);
                $errorDetail = $decoded['error']['message'] ?? $responseBody;
            }
            throw new \RuntimeException(sprintf('OpenAI API error (HTTP %d): %s', $httpCode, $errorDetail));
        }

        $decoded = json_decode((string) $responseBody, true);
        if (!is_array($decoded)) {
            throw new \RuntimeException('OpenAI API returned invalid JSON.');
        }

        return $decoded;
    }

    /**
     * @param array<string, mixed> $apiResponse
     * @return array<string, string>
     */
    private function parseResponse(array $apiResponse, string $cmsProfile): array
    {
        $content = $apiResponse['choices'][0]['message']['content'] ?? '';
        if ($content === '') {
            throw new \RuntimeException('OpenAI API returned empty content.');
        }

        $parsed = json_decode($content, true);
        if (!is_array($parsed)) {
            throw new \RuntimeException('OpenAI returned non-JSON content: ' . mb_substr($content, 0, 200));
        }

        // Normalize and validate required fields
        $slug = preg_replace('/[^a-z0-9-]/', '', strtolower(str_replace(' ', '-', $parsed['slug'] ?? '')));
        if ($slug === '') {
            $slug = preg_replace('/[^a-z0-9-]/', '', strtolower(str_replace(' ', '-', $parsed['title'] ?? 'untitled')));
        }

        return [
            'cms_profile'      => $cmsProfile,
            'title'            => $parsed['title'] ?? 'Untitled Post',
            'slug'             => substr($slug, 0, 60),
            'content'          => $parsed['content'] ?? '<p>Content could not be generated.</p>',
            'excerpt'          => $parsed['excerpt'] ?? '',
            'author'           => $parsed['author'] ?? 'admin',
            'category'         => $parsed['category'] ?? 'Uncategorized',
            'meta_description' => substr($parsed['meta_description'] ?? '', 0, 160),
            'content_type'     => 'post',
            'status'           => 'published',
            'published_date'   => date('Y-m-d H:i:s'),
        ];
    }

    /**
     * @return string[]
     */
    private function generateTopicVariations(string $niche, int $count): array
    {
        $variations = [
            'Getting started with ' . $niche,
            'Top tips for ' . $niche . ' success',
            'Common mistakes in ' . $niche,
            'The future of ' . $niche,
            'How to improve your ' . $niche . ' strategy',
            'A beginner\'s guide to ' . $niche,
            'Best practices for ' . $niche,
            'Why ' . $niche . ' matters for your business',
            $niche . ' trends you should know',
            'Expert advice on ' . $niche,
        ];

        $topics = [];
        for ($i = 0; $i < $count; $i++) {
            $topics[] = $variations[$i % count($variations)];
        }

        return $topics;
    }
}
