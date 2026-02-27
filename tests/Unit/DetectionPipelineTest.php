<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Detection\DetectionPipeline;
use ReportedIp\Honeypot\Tests\TestCase;

final class DetectionPipelineTest extends TestCase
{
    public function testCreateDefaultLoads36Analyzers(): void
    {
        $pipeline = DetectionPipeline::createDefault();
        $this->t->assertEquals(36, $pipeline->getAnalyzerCount());
    }

    public function testEmptyPipelineReturnsNoResults(): void
    {
        $pipeline = new DetectionPipeline();
        $request = $this->createRequest(['uri' => '/', 'method' => 'GET']);
        $results = $pipeline->analyze($request);
        $this->t->assertEmpty($results);
    }

    public function testAnalyzeDetectsAttack(): void
    {
        $pipeline = DetectionPipeline::createDefault();
        $request = $this->createRequest([
            'uri' => "/page?id=1' UNION SELECT username,password FROM users--",
        ]);
        $results = $pipeline->analyze($request);
        $this->t->assertNotEmpty($results);
    }

    public function testAnalyzeReturnsDetectionResults(): void
    {
        $pipeline = DetectionPipeline::createDefault();
        $request = $this->createRequest([
            'uri'     => '/wp-login.php',
            'method'  => 'POST',
            'headers' => ['User-Agent' => 'sqlmap/1.5'],
            'postData' => ['log' => 'admin', 'pwd' => 'password'],
        ]);
        $results = $pipeline->analyze($request);
        $this->t->assertNotEmpty($results);

        foreach ($results as $result) {
            $this->t->assertInstanceOf(\ReportedIp\Honeypot\Detection\DetectionResult::class, $result);
            $this->t->assertNotEmpty($result->getCategories());
            $this->t->assertNotEquals('', $result->getComment());
            $this->t->assertGreaterThan(0, $result->getScore());
        }
    }

    public function testCleanRequestProducesMinimalResults(): void
    {
        $pipeline = DetectionPipeline::createDefault();
        $request = $this->createRequest([
            'uri'     => '/about',
            'method'  => 'GET',
            'headers' => [
                'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
                'Accept'     => 'text/html',
                'Host'       => 'example.com',
            ],
        ]);
        $results = $pipeline->analyze($request);
        // A clean request to /about should produce very few or no detections
        // PathScanning might flag it as not_found, but shouldn't produce high-confidence results
        $highScore = 0;
        foreach ($results as $r) {
            if ($r->getScore() > $highScore) {
                $highScore = $r->getScore();
            }
        }
        // We don't expect high-confidence detections on clean traffic
        $this->t->assertLessThanOrEqual(50, $highScore);
    }

    public function testAddAnalyzerIncreasesCount(): void
    {
        $pipeline = new DetectionPipeline();
        $this->t->assertEquals(0, $pipeline->getAnalyzerCount());

        $pipeline->addAnalyzer(new \ReportedIp\Honeypot\Detection\Analyzers\SqlInjectionAnalyzer());
        $this->t->assertEquals(1, $pipeline->getAnalyzerCount());
    }
}
