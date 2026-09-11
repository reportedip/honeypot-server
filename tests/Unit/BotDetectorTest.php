<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Detection\BotDetector;
use ReportedIp\Honeypot\Tests\TestCase;

final class BotDetectorTest extends TestCase
{
    public function testDetectsOaiSearchBot(): void
    {
        $ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36; compatible; OAI-SearchBot/1.4; robots.txt; +https://openai.com/searchbot';

        $this->t->assertTrue(BotDetector::isLegitimateBot($ua));

        $classification = BotDetector::classify($ua);
        $this->t->assertEquals('ai_agent', $classification['type']);
        $this->t->assertEquals('OpenAI SearchBot', $classification['name']);
    }

    public function testDetectsGptBot(): void
    {
        $ua = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)';

        $this->t->assertTrue(BotDetector::isLegitimateBot($ua));

        $classification = BotDetector::classify($ua);
        $this->t->assertEquals('ai_agent', $classification['type']);
        $this->t->assertEquals('GPTBot (OpenAI)', $classification['name']);
    }

    public function testDetectsGooglebot(): void
    {
        $ua = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

        $this->t->assertTrue(BotDetector::isLegitimateBot($ua));

        $classification = BotDetector::classify($ua);
        $this->t->assertEquals('good_bot', $classification['type']);
        $this->t->assertEquals('Googlebot', $classification['name']);
    }

    public function testDetectsGoogleOther(): void
    {
        $ua = 'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36 (compatible; GoogleOther)';

        $this->t->assertTrue(BotDetector::isLegitimateBot($ua));

        $classification = BotDetector::classify($ua);
        $this->t->assertEquals('good_bot', $classification['type']);
        $this->t->assertEquals('GoogleOther', $classification['name']);
    }

    public function testClassifiesCurlAsBadBot(): void
    {
        $ua = 'curl/8.4.0';

        $this->t->assertFalse(BotDetector::isLegitimateBot($ua));

        $classification = BotDetector::classify($ua);
        $this->t->assertEquals('bad_bot', $classification['type']);
        $this->t->assertEquals('curl', $classification['name']);
    }

    public function testClassifiesHumanBrowser(): void
    {
        $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

        $this->t->assertFalse(BotDetector::isLegitimateBot($ua));

        $classification = BotDetector::classify($ua);
        $this->t->assertEquals('human', $classification['type']);
        $this->t->assertEquals('', $classification['name']);
    }

    public function testHandlesEmptyUserAgent(): void
    {
        $this->t->assertFalse(BotDetector::isLegitimateBot(''));

        $classification = BotDetector::classify('');
        $this->t->assertEquals('bad_bot', $classification['type']);
        $this->t->assertEquals('Empty UA', $classification['name']);
    }
}
