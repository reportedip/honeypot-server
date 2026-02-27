<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Analyzers;

use ReportedIp\Honeypot\Detection\Analyzers\ConfigAccessAnalyzer;
use ReportedIp\Honeypot\Tests\TestCase;

final class ConfigAccessAnalyzerTest extends TestCase
{
    private ConfigAccessAnalyzer $analyzer;

    public function setUp(): void
    {
        $this->analyzer = new ConfigAccessAnalyzer();
    }

    public function testGetName(): void
    {
        $this->t->assertEquals('ConfigAccess', $this->analyzer->getName());
    }

    // --- Positive tests ---

    public function testDetectsWpConfigPhpBak(): void
    {
        $request = $this->createRequest(['uri' => '/wp-config.php.bak']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertGreaterThanOrEqual(80, $result->getScore());
    }

    public function testDetectsEnvFile(): void
    {
        $request = $this->createRequest(['uri' => '/.env']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsEnvProduction(): void
    {
        $request = $this->createRequest(['uri' => '/.env.production']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsWpConfigPhp(): void
    {
        $request = $this->createRequest(['uri' => '/wp-config.php']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertGreaterThanOrEqual(85, $result->getScore());
    }

    public function testDetectsDrupalSettings(): void
    {
        $request = $this->createRequest(['uri' => '/sites/default/settings.php']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsSecretsJson(): void
    {
        $request = $this->createRequest(['uri' => '/secrets.json']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsConfigIncPhp(): void
    {
        $request = $this->createRequest(['uri' => '/config.inc.php']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsDatabaseYml(): void
    {
        $request = $this->createRequest(['uri' => '/database.yml']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    // --- Negative tests ---

    public function testIgnoresNormalPages(): void
    {
        $request = $this->createRequest(['uri' => '/about']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testIgnoresRootPath(): void
    {
        $request = $this->createRequest(['uri' => '/']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testIgnoresNormalCssFile(): void
    {
        $request = $this->createRequest(['uri' => '/style.css']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testCategoriesAre58And15(): void
    {
        $request = $this->createRequest(['uri' => '/wp-config.php.bak']);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $categories = $result->getCategories();
        $this->t->assertTrue(in_array(58, $categories, true), 'Should include category 58');
        $this->t->assertTrue(in_array(15, $categories, true), 'Should include category 15');
    }
}
