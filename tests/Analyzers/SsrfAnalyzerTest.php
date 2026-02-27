<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Analyzers;

use ReportedIp\Honeypot\Detection\Analyzers\SsrfAnalyzer;
use ReportedIp\Honeypot\Tests\TestCase;

final class SsrfAnalyzerTest extends TestCase
{
    private SsrfAnalyzer $analyzer;

    public function setUp(): void
    {
        $this->analyzer = new SsrfAnalyzer();
    }

    public function testGetName(): void
    {
        $this->t->assertEquals('SSRF', $this->analyzer->getName());
    }

    // --- Positive tests ---

    public function testDetectsLocalhostInParam(): void
    {
        $request = $this->createRequest(['uri' => '/fetch?url=http://localhost/admin']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsInternalIp(): void
    {
        $request = $this->createRequest(['uri' => '/proxy?url=http://192.168.1.1/admin']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsCloudMetadata(): void
    {
        $request = $this->createRequest(['uri' => '/proxy?url=http://169.254.169.254/latest/meta-data/']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertGreaterThanOrEqual(80, $result->getScore());
    }

    public function testDetectsFileProtocol(): void
    {
        $request = $this->createRequest(['uri' => '/proxy?url=file:///etc/passwd']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsGopherProtocol(): void
    {
        $request = $this->createRequest(['uri' => '/fetch?url=gopher://internal:25/']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetects127IpRange(): void
    {
        $request = $this->createRequest(['uri' => '/api?redirect=http://127.0.0.1:8080/admin']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsPrivate10Range(): void
    {
        $request = $this->createRequest([
            'uri'        => '/api',
            'queryParams' => ['target' => 'http://10.0.0.1/internal'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    // --- Negative tests ---

    public function testIgnoresNormalExternalUrl(): void
    {
        $request = $this->createRequest(['uri' => '/page?ref=https://www.example.com/about']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testIgnoresNormalParams(): void
    {
        $request = $this->createRequest(['uri' => '/search?q=hello+world']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testCategoryIs21(): void
    {
        $request = $this->createRequest(['uri' => '/proxy?url=http://127.0.0.1/']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertTrue(in_array(21, $result->getCategories(), true), 'Should include category 21');
    }
}
