<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Analyzers;

use ReportedIp\Honeypot\Detection\Analyzers\SqlInjectionAnalyzer;
use ReportedIp\Honeypot\Tests\TestCase;

final class SqlInjectionAnalyzerTest extends TestCase
{
    private SqlInjectionAnalyzer $analyzer;

    public function setUp(): void
    {
        $this->analyzer = new SqlInjectionAnalyzer();
    }

    public function testGetName(): void
    {
        $this->t->assertEquals('SqlInjection', $this->analyzer->getName());
    }

    // --- Positive tests ---

    public function testDetectsUnionSelect(): void
    {
        $request = $this->createRequest(['uri' => "/page?id=1' UNION SELECT username,password FROM users--"]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertTrue(in_array(16, $result->getCategories(), true));
        $this->t->assertTrue(in_array(45, $result->getCategories(), true));
    }

    public function testDetectsSleepInjection(): void
    {
        $request = $this->createRequest(['uri' => "/page?id=1 AND SLEEP(5)"]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsEncodedSqli(): void
    {
        $request = $this->createRequest(['uri' => "/page?id=1%27%20UNION%20SELECT%201"]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsSqlmapUserAgent(): void
    {
        $request = $this->createRequest([
            'uri'     => '/page?id=1',
            'headers' => ['User-Agent' => 'sqlmap/1.5.2#stable'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertGreaterThanOrEqual(90, $result->getScore());
    }

    public function testDetectsPostDataSqli(): void
    {
        $request = $this->createRequest([
            'uri'      => '/login',
            'method'   => 'POST',
            'postData' => ['username' => "admin' UNION SELECT password FROM users--"],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsBenchmark(): void
    {
        $request = $this->createRequest(['uri' => "/page?id=1 AND BENCHMARK(10000000,SHA1('test'))"]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsInformationSchema(): void
    {
        $request = $this->createRequest(['uri' => "/page?id=1 UNION SELECT table_name FROM information_schema.tables"]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsStackedQuery(): void
    {
        $request = $this->createRequest(['uri' => "/page?id=1; DROP TABLE users"]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsDoubleEncoded(): void
    {
        $request = $this->createRequest(['uri' => "/page?id=%2527"]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    // --- Negative tests ---

    public function testIgnoresNormalQuery(): void
    {
        $request = $this->createRequest(['uri' => '/products?category=shoes&page=2']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testIgnoresHomePage(): void
    {
        $request = $this->createRequest(['uri' => '/']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testIgnoresNormalPostData(): void
    {
        $request = $this->createRequest([
            'uri'      => '/contact',
            'method'   => 'POST',
            'postData' => ['name' => 'John', 'message' => 'Hello there'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testCategoriesAre16And45(): void
    {
        $request = $this->createRequest(['uri' => "/page?id=1' UNION SELECT 1"]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $categories = $result->getCategories();
        $this->t->assertTrue(in_array(16, $categories, true), 'Should include category 16');
        $this->t->assertTrue(in_array(45, $categories, true), 'Should include category 45');
    }
}
