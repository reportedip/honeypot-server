<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Api\WebhookDispatcher;
use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Detection\DetectionResult;
use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Persistence\WebhookRepository;
use ReportedIp\Honeypot\Tests\TestCase;

final class WebhookDispatcherTest extends TestCase
{
    private string $dbPath;
    private Database $db;
    private WebhookRepository $repo;
    private WebhookDispatcher $dispatcher;

    public function setUp(): void
    {
        $this->dbPath = sys_get_temp_dir() . '/honeypot_dispatcher_test_' . uniqid() . '.sqlite';
        $this->db = new Database($this->dbPath);
        $this->db->initialize();
        $this->repo = new WebhookRepository($this->db);
        $this->dispatcher = new WebhookDispatcher($this->repo, new Config([]));
    }

    public function tearDown(): void
    {
        @unlink($this->dbPath);
    }

    private function makeResult(array $categories = [16], string $analyzer = 'SqlInjection'): DetectionResult
    {
        return new DetectionResult($categories, 'test detection', 80, $analyzer);
    }

    // --- Matching ---

    public function testEmptyFiltersMatchEverything(): void
    {
        $webhook = ['categories' => '', 'analyzers' => ''];
        $this->t->assertTrue(WebhookDispatcher::shouldTrigger($webhook, $this->makeResult()));
    }

    public function testCategoryFilterMatches(): void
    {
        $webhook = ['categories' => '16,18', 'analyzers' => ''];
        $this->t->assertTrue(WebhookDispatcher::shouldTrigger($webhook, $this->makeResult([16, 45])));
    }

    public function testCategoryFilterRejectsNonMatching(): void
    {
        $webhook = ['categories' => '18,31', 'analyzers' => ''];
        $this->t->assertFalse(WebhookDispatcher::shouldTrigger($webhook, $this->makeResult([16, 45])));
    }

    public function testAnalyzerFilterMatches(): void
    {
        $webhook = ['categories' => '', 'analyzers' => 'SqlInjection,Xss'];
        $this->t->assertTrue(WebhookDispatcher::shouldTrigger($webhook, $this->makeResult([16], 'SqlInjection')));
    }

    public function testAnalyzerFilterRejectsNonMatching(): void
    {
        $webhook = ['categories' => '', 'analyzers' => 'BruteForce'];
        $this->t->assertFalse(WebhookDispatcher::shouldTrigger($webhook, $this->makeResult([16], 'SqlInjection')));
    }

    public function testEitherFilterMatchingTriggers(): void
    {
        // Kategorie passt nicht, aber Analyzer passt — ODER-Logik
        $webhook = ['categories' => '31', 'analyzers' => 'SqlInjection'];
        $this->t->assertTrue(WebhookDispatcher::shouldTrigger($webhook, $this->makeResult([16], 'SqlInjection')));
    }

    public function testNeitherFilterMatchingRejects(): void
    {
        $webhook = ['categories' => '31', 'analyzers' => 'BruteForce'];
        $this->t->assertFalse(WebhookDispatcher::shouldTrigger($webhook, $this->makeResult([16], 'SqlInjection')));
    }

    // --- Payload ---

    public function testBuildPayloadStructure(): void
    {
        $request = $this->createRequest([
            'uri'    => '/wp-login.php?test=1',
            'method' => 'POST',
            'ip'     => '203.0.113.50',
        ]);
        $request->setIp('203.0.113.50');

        $results = [$this->makeResult([16, 45], 'SqlInjection')];
        $payload = $this->dispatcher->buildPayload($request, $results);

        $this->t->assertEquals('detection', $payload['event']);
        $this->t->assertEquals('203.0.113.50', $payload['request']['ip']);
        $this->t->assertEquals('POST', $payload['request']['method']);
        $this->t->assertEquals('/wp-login.php?test=1', $payload['request']['uri']);
        $this->t->assertEquals(1, count($payload['detections']));
        $this->t->assertEquals('SqlInjection', $payload['detections'][0]['analyzer']);
        $this->t->assertEquals([16, 45], $payload['detections'][0]['categories']);
        $this->t->assertEquals(80, $payload['detections'][0]['severity']);
        $this->t->assertTrue(isset($payload['detections'][0]['category_names'][0]));
        $this->t->assertTrue(isset($payload['honeypot']['version']));
        $this->t->assertTrue(isset($payload['generated_at']));
    }

    // --- Signatur ---

    public function testSignProducesHmacSha256(): void
    {
        $body = '{"event":"test"}';
        $secret = 'my-secret';
        $expected = 'sha256=' . hash_hmac('sha256', $body, $secret);
        $this->t->assertEquals($expected, WebhookDispatcher::sign($body, $secret));
    }

    // --- Dispatch (ohne erreichbare URL: Fehler werden gezählt, nichts wirft) ---

    public function testDispatchSkipsNonMatchingWebhooks(): void
    {
        // Webhook matcht die Detection nicht — es darf kein HTTP-Versuch erfolgen
        $id = $this->repo->add([
            'name'       => 'NoMatch',
            'url'        => 'https://unreachable.invalid/hook',
            'categories' => '31',
            'analyzers'  => 'BruteForce',
        ]);

        $request = $this->createRequest(['ip' => '203.0.113.50']);
        $delivered = $this->dispatcher->dispatch($request, [$this->makeResult([16], 'SqlInjection')]);

        $this->t->assertEquals(0, $delivered);
        $webhook = $this->repo->getById($id);
        // Kein Versuch → keine Status-Änderung
        $this->t->assertEquals('', (string) $webhook['last_status']);
    }

    public function testDispatchSkipsDisabledWebhooks(): void
    {
        $id = $this->repo->add([
            'name' => 'Disabled',
            'url'  => 'https://unreachable.invalid/hook',
        ]);
        $this->repo->setEnabled($id, false);

        $request = $this->createRequest(['ip' => '203.0.113.50']);
        $delivered = $this->dispatcher->dispatch($request, [$this->makeResult()]);

        $this->t->assertEquals(0, $delivered);
    }
}
