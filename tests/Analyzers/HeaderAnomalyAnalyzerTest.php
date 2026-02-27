<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Analyzers;

use ReportedIp\Honeypot\Detection\Analyzers\HeaderAnomalyAnalyzer;
use ReportedIp\Honeypot\Tests\TestCase;

final class HeaderAnomalyAnalyzerTest extends TestCase
{
    private HeaderAnomalyAnalyzer $analyzer;

    public function setUp(): void
    {
        $this->analyzer = new HeaderAnomalyAnalyzer();
    }

    public function testGetName(): void
    {
        $this->t->assertEquals('HeaderAnomaly', $this->analyzer->getName());
    }

    // --- Positive tests ---

    public function testDetectsMissingHostHeader(): void
    {
        // Create request without Host header
        $request = $this->createRequest(['uri' => '/page', 'headers' => ['Host' => '', 'User-Agent' => '']]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertContains('Host', $result->getComment());
    }

    public function testDetectsCrlfInjection(): void
    {
        $request = $this->createRequest([
            'uri'     => '/page',
            'headers' => [
                'Host'    => 'example.com',
                'X-Custom' => "value%0d%0aInjected: header",
            ],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertContains('CRLF', $result->getComment());
    }

    public function testDetectsAttackPayloadInReferer(): void
    {
        $request = $this->createRequest([
            'uri'     => '/page',
            'headers' => [
                'Host'    => 'example.com',
                'Referer' => '<script>alert(1)</script>',
            ],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertContains('Referer', $result->getComment());
    }

    public function testDetectsMethodOverrideHeader(): void
    {
        $request = $this->createRequest([
            'uri'     => '/page',
            'headers' => [
                'Host'                   => 'example.com',
                'X-HTTP-Method-Override' => 'DELETE',
            ],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsSuspiciousXff(): void
    {
        $request = $this->createRequest([
            'uri'     => '/page',
            'headers' => [
                'Host'            => 'example.com',
                'X-Forwarded-For' => '127.0.0.1',
            ],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    // --- Negative tests ---

    public function testIgnoresNormalHeaders(): void
    {
        $request = $this->createRequest([
            'uri'     => '/page',
            'headers' => [
                'Host'       => 'example.com',
                'User-Agent' => 'Mozilla/5.0 Chrome/120',
                'Accept'     => 'text/html',
            ],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testCategoriesAre15And21(): void
    {
        $request = $this->createRequest(['uri' => '/page', 'headers' => ['Host' => '', 'User-Agent' => '']]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $categories = $result->getCategories();
        $this->t->assertTrue(in_array(15, $categories, true), 'Should include category 15');
        $this->t->assertTrue(in_array(21, $categories, true), 'Should include category 21');
    }
}
