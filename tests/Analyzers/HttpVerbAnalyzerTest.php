<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Analyzers;

use ReportedIp\Honeypot\Detection\Analyzers\HttpVerbAnalyzer;
use ReportedIp\Honeypot\Tests\TestCase;

final class HttpVerbAnalyzerTest extends TestCase
{
    private HttpVerbAnalyzer $analyzer;

    public function setUp(): void
    {
        $this->analyzer = new HttpVerbAnalyzer();
    }

    public function testGetName(): void
    {
        $this->t->assertEquals('HttpVerb', $this->analyzer->getName());
    }

    // --- Positive tests ---

    public function testDetectsTraceMethod(): void
    {
        $request = $this->createRequest(['uri' => '/', 'method' => 'TRACE']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertContains('TRACE', $result->getComment());
    }

    public function testDetectsPropfindMethod(): void
    {
        $request = $this->createRequest(['uri' => '/', 'method' => 'PROPFIND']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsConnectMethod(): void
    {
        $request = $this->createRequest(['uri' => '/', 'method' => 'CONNECT']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertGreaterThanOrEqual(70, $result->getScore());
    }

    public function testDetectsDebugMethod(): void
    {
        $request = $this->createRequest(['uri' => '/', 'method' => 'DEBUG']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsUnknownMethod(): void
    {
        $request = $this->createRequest(['uri' => '/', 'method' => 'FUZZ']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsMethodOverrideHeader(): void
    {
        $request = $this->createRequest([
            'uri'     => '/',
            'method'  => 'POST',
            'headers' => ['X-HTTP-Method-Override' => 'DELETE'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    // --- Negative tests ---

    public function testIgnoresGetMethod(): void
    {
        $request = $this->createRequest(['uri' => '/', 'method' => 'GET']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testIgnoresPostMethod(): void
    {
        $request = $this->createRequest(['uri' => '/', 'method' => 'POST']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testIgnoresHeadMethod(): void
    {
        $request = $this->createRequest(['uri' => '/', 'method' => 'HEAD']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testIgnoresOptionsMethod(): void
    {
        $request = $this->createRequest(['uri' => '/', 'method' => 'OPTIONS']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testCategoryIs21(): void
    {
        $request = $this->createRequest(['uri' => '/', 'method' => 'TRACE']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertTrue(in_array(21, $result->getCategories(), true), 'Should include category 21');
    }
}
