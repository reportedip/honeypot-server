<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Analyzers;

use ReportedIp\Honeypot\Detection\Analyzers\PathTraversalAnalyzer;
use ReportedIp\Honeypot\Tests\TestCase;

final class PathTraversalAnalyzerTest extends TestCase
{
    private PathTraversalAnalyzer $analyzer;

    public function setUp(): void
    {
        $this->analyzer = new PathTraversalAnalyzer();
    }

    public function testGetName(): void
    {
        $this->t->assertEquals('PathTraversal', $this->analyzer->getName());
    }

    // --- Positive tests ---

    public function testDetectsBasicTraversal(): void
    {
        $request = $this->createRequest(['uri' => '/page?file=../../../etc/passwd']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertGreaterThanOrEqual(75, $result->getScore());
    }

    public function testDetectsEncodedTraversal(): void
    {
        $request = $this->createRequest(['uri' => '/page?file=%2e%2e%2f%2e%2e%2fetc/passwd']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsPhpFilterWrapper(): void
    {
        $request = $this->createRequest(['uri' => '/page?file=php://filter/convert.base64-encode/resource=index.php']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertGreaterThanOrEqual(75, $result->getScore());
    }

    public function testDetectsPhpInputWrapper(): void
    {
        $request = $this->createRequest(['uri' => '/page?file=php://input']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsNullByte(): void
    {
        $request = $this->createRequest(['uri' => '/page?file=../../../etc/passwd%00.jpg']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsWindowsPath(): void
    {
        $request = $this->createRequest(['uri' => '/page?file=C:\\windows\\system32\\config']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsEtcShadow(): void
    {
        $request = $this->createRequest(['uri' => '/page?file=../../../../etc/shadow']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertGreaterThanOrEqual(75, $result->getScore());
    }

    public function testDetectsPharWrapper(): void
    {
        $request = $this->createRequest(['uri' => '/page?file=phar://upload/evil.phar/shell.php']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsDoubleEncoded(): void
    {
        $request = $this->createRequest(['uri' => '/page?file=%252e%252e%252f']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    // --- Negative tests ---

    public function testIgnoresNormalPaths(): void
    {
        $request = $this->createRequest(['uri' => '/images/logo.png']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testIgnoresNormalQueryParams(): void
    {
        $request = $this->createRequest(['uri' => '/page?category=electronics&page=2']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testCategoryIs21(): void
    {
        $request = $this->createRequest(['uri' => '/page?file=../../../etc/passwd']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertTrue(in_array(21, $result->getCategories(), true), 'Should include category 21');
    }
}
