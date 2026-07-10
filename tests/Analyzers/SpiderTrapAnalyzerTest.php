<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Analyzers;

use ReportedIp\Honeypot\Detection\Analyzers\SpiderTrapAnalyzer;
use ReportedIp\Honeypot\Detection\SpiderTrap;
use ReportedIp\Honeypot\Tests\TestCase;

final class SpiderTrapAnalyzerTest extends TestCase
{
    private SpiderTrapAnalyzer $analyzer;

    public function setUp(): void
    {
        $this->analyzer = new SpiderTrapAnalyzer();
    }

    public function testGetName(): void
    {
        $this->t->assertEquals('SpiderTrap', $this->analyzer->getName());
    }

    public function testDetectsRobotsBaitPath(): void
    {
        $result = $this->analyzer->analyze($this->createRequest(['uri' => SpiderTrap::robotsPath()]));
        $this->t->assertNotNull($result);
        $this->t->assertTrue(in_array(63, $result->getCategories(), true));
    }

    public function testDetectsHiddenBaitPath(): void
    {
        $result = $this->analyzer->analyze($this->createRequest(['uri' => SpiderTrap::hiddenPath()]));
        $this->t->assertNotNull($result);
    }

    public function testDetectsBaitPathWithoutTrailingSlash(): void
    {
        $result = $this->analyzer->analyze($this->createRequest(['uri' => rtrim(SpiderTrap::sitemapPath(), '/')]));
        $this->t->assertNotNull($result);
    }

    public function testIgnoresNormalPath(): void
    {
        $result = $this->analyzer->analyze($this->createRequest(['uri' => '/about-us/']));
        $this->t->assertNull($result);
    }
}
