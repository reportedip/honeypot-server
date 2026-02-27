<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Analyzers;

use ReportedIp\Honeypot\Detection\Analyzers\PathScanningAnalyzer;
use ReportedIp\Honeypot\Tests\TestCase;

final class PathScanningAnalyzerTest extends TestCase
{
    private PathScanningAnalyzer $analyzer;

    public function setUp(): void
    {
        $this->analyzer = new PathScanningAnalyzer();
    }

    public function testGetName(): void
    {
        $this->t->assertEquals('PathScanning', $this->analyzer->getName());
    }

    // --- Positive tests ---

    public function testDetectsEnvFile(): void
    {
        $request = $this->createRequest(['uri' => '/.env']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertGreaterThanOrEqual(60, $result->getScore());
    }

    public function testDetectsGitDirectory(): void
    {
        $request = $this->createRequest(['uri' => '/.git/HEAD']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsPhpinfo(): void
    {
        $request = $this->createRequest(['uri' => '/phpinfo.php']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsBackupFile(): void
    {
        $request = $this->createRequest(['uri' => '/index.php.bak']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsSqlDump(): void
    {
        $request = $this->createRequest(['uri' => '/database.sql']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsPhpMyAdmin(): void
    {
        $request = $this->createRequest(['uri' => '/phpmyadmin/']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsLogFile(): void
    {
        $request = $this->createRequest(['uri' => '/error.log']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsComposerJson(): void
    {
        $request = $this->createRequest(['uri' => '/composer.json']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    // --- Negative tests ---

    public function testIgnoresRootPath(): void
    {
        $request = $this->createRequest(['uri' => '/']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testIgnoresNormalPages(): void
    {
        $request = $this->createRequest(['uri' => '/about-us']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testIgnoresNormalImages(): void
    {
        $request = $this->createRequest(['uri' => '/images/photo.jpg']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testCategoriesAre14And15(): void
    {
        $request = $this->createRequest(['uri' => '/.env']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $categories = $result->getCategories();
        $this->t->assertTrue(in_array(14, $categories, true), 'Should include category 14');
        $this->t->assertTrue(in_array(15, $categories, true), 'Should include category 15');
    }
}
