<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Analyzers;

use ReportedIp\Honeypot\Detection\Analyzers\ForeignFrameworkProbeAnalyzer;
use ReportedIp\Honeypot\Tests\TestCase;

final class ForeignFrameworkProbeAnalyzerTest extends TestCase
{
    private ForeignFrameworkProbeAnalyzer $analyzer;

    public function setUp(): void
    {
        $this->analyzer = new ForeignFrameworkProbeAnalyzer();
    }

    public function testGetName(): void
    {
        $this->t->assertEquals('ForeignFrameworkProbe', $this->analyzer->getName());
    }

    public function testDetectsTomcatManager(): void
    {
        $result = $this->analyzer->analyze($this->createRequest(['uri' => '/manager/html']));
        $this->t->assertNotNull($result);
        $this->t->assertTrue(in_array(61, $result->getCategories(), true));
    }

    public function testDetectsSolr(): void
    {
        $result = $this->analyzer->analyze($this->createRequest(['uri' => '/solr/admin/cores']));
        $this->t->assertNotNull($result);
    }

    public function testDetectsWebLogicWsat(): void
    {
        $result = $this->analyzer->analyze($this->createRequest(['uri' => '/wls-wsat/CoordinatorPortType']));
        $this->t->assertNotNull($result);
    }

    public function testDetectsSpringActuatorEnv(): void
    {
        $result = $this->analyzer->analyze($this->createRequest(['uri' => '/actuator/env']));
        $this->t->assertNotNull($result);
    }

    public function testIgnoresNormalCmsPath(): void
    {
        $result = $this->analyzer->analyze($this->createRequest(['uri' => '/wp-login.php']));
        $this->t->assertNull($result);
    }

    public function testIgnoresRoot(): void
    {
        $result = $this->analyzer->analyze($this->createRequest(['uri' => '/']));
        $this->t->assertNull($result);
    }

    public function testDetectsOpenVisitorsIotProbe(): void
    {
        $result = $this->analyzer->analyze($this->createRequest(['uri' => '/open/visitors/info/gets?uuid=1']));
        $this->t->assertNotNull($result);
        $this->t->assertTrue(in_array(61, $result->getCategories(), true));
    }
}
