<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Analyzers;

use ReportedIp\Honeypot\Detection\Analyzers\WebshellAccessAnalyzer;
use ReportedIp\Honeypot\Tests\TestCase;

final class WebshellAccessAnalyzerTest extends TestCase
{
    private WebshellAccessAnalyzer $analyzer;

    public function setUp(): void
    {
        $this->analyzer = new WebshellAccessAnalyzer();
    }

    public function testGetName(): void
    {
        $this->t->assertEquals('WebshellAccess', $this->analyzer->getName());
    }

    public function testDetectsKnownShellFilename(): void
    {
        $result = $this->analyzer->analyze($this->createRequest(['uri' => '/wso.php']));
        $this->t->assertNotNull($result);
        $this->t->assertGreaterThanOrEqual(85, $result->getScore());
        $this->t->assertTrue(in_array(60, $result->getCategories(), true));
    }

    public function testDetectsShellInUploadsDir(): void
    {
        $result = $this->analyzer->analyze($this->createRequest(['uri' => '/wp-content/uploads/2024/09/evil.php']));
        $this->t->assertNotNull($result);
    }

    public function testDetectsDoubleExtension(): void
    {
        $result = $this->analyzer->analyze($this->createRequest(['uri' => '/uploads/invoice.jpg.php']));
        $this->t->assertNotNull($result);
    }

    public function testIgnoresNormalPhpPage(): void
    {
        $result = $this->analyzer->analyze($this->createRequest(['uri' => '/index.php']));
        $this->t->assertNull($result);
    }

    public function testIgnoresRoot(): void
    {
        $result = $this->analyzer->analyze($this->createRequest(['uri' => '/']));
        $this->t->assertNull($result);
    }

    public function testIgnoresRegularImageInUploads(): void
    {
        $result = $this->analyzer->analyze($this->createRequest(['uri' => '/wp-content/uploads/2024/09/photo.jpg']));
        $this->t->assertNull($result);
    }
}
