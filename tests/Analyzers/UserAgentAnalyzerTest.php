<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Analyzers;

use ReportedIp\Honeypot\Detection\Analyzers\UserAgentAnalyzer;
use ReportedIp\Honeypot\Tests\TestCase;

final class UserAgentAnalyzerTest extends TestCase
{
    private UserAgentAnalyzer $analyzer;

    public function setUp(): void
    {
        $this->analyzer = new UserAgentAnalyzer();
    }

    public function testGetName(): void
    {
        $this->t->assertEquals('UserAgent', $this->analyzer->getName());
    }

    // --- Positive tests ---

    public function testDetectsSqlmap(): void
    {
        $request = $this->createRequest([
            'uri'     => '/',
            'headers' => ['User-Agent' => 'sqlmap/1.5.2#stable (http://sqlmap.org)'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertGreaterThanOrEqual(75, $result->getScore());
    }

    public function testDetectsNikto(): void
    {
        $request = $this->createRequest([
            'uri'     => '/',
            'headers' => ['User-Agent' => 'Mozilla/5.0 (nikto/2.1.6)'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsEmptyUserAgent(): void
    {
        $request = $this->createRequest([
            'uri' => '/',
            'headers' => ['Host' => 'example.com', 'User-Agent' => ''],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertContains('Empty', $result->getComment());
    }

    public function testDetectsNmap(): void
    {
        $request = $this->createRequest([
            'uri'     => '/',
            'headers' => ['User-Agent' => 'Nmap Scripting Engine'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsCurl(): void
    {
        $request = $this->createRequest([
            'uri'     => '/',
            'headers' => ['User-Agent' => 'curl/7.88.1'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsPythonRequests(): void
    {
        $request = $this->createRequest([
            'uri'     => '/',
            'headers' => ['User-Agent' => 'python-requests/2.28.1'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsScrapy(): void
    {
        $request = $this->createRequest([
            'uri'     => '/',
            'headers' => ['User-Agent' => 'Scrapy/2.8.0'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    // --- Negative tests ---

    public function testIgnoresChromeBrowser(): void
    {
        $request = $this->createRequest([
            'uri'     => '/',
            'headers' => ['User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testIgnoresFirefoxBrowser(): void
    {
        $request = $this->createRequest([
            'uri'     => '/',
            'headers' => ['User-Agent' => 'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testIgnoresGooglebot(): void
    {
        $request = $this->createRequest([
            'uri'     => '/',
            'headers' => ['User-Agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testCategoriesAre19And49(): void
    {
        $request = $this->createRequest([
            'uri'     => '/',
            'headers' => ['User-Agent' => 'sqlmap/1.5'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $categories = $result->getCategories();
        $this->t->assertTrue(in_array(19, $categories, true), 'Should include category 19');
        $this->t->assertTrue(in_array(49, $categories, true), 'Should include category 49');
    }
}
