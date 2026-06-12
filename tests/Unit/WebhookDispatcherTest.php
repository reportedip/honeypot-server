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

    // --- AbuseIPDB-Kategorie-Mapping ---

    public function testAbuseIpDbMappingPassesThroughSharedCategories(): void
    {
        // 1-23 sind bei reportedip.de und AbuseIPDB identisch
        $this->t->assertEquals([16, 18], WebhookDispatcher::mapCategoriesToAbuseIpDb([16, 18]));
    }

    public function testAbuseIpDbMappingTranslatesCmsCategories(): void
    {
        // 31 WP Login Brute Force -> 18 Brute-Force + 21 Web App Attack
        $this->t->assertEquals([18, 21], WebhookDispatcher::mapCategoriesToAbuseIpDb([31]));
        // 44 XSS -> 21 Web App Attack
        $this->t->assertEquals([21], WebhookDispatcher::mapCategoriesToAbuseIpDb([44]));
        // 40 Form Spam -> 10 Web Spam
        $this->t->assertEquals([10], WebhookDispatcher::mapCategoriesToAbuseIpDb([40]));
    }

    public function testAbuseIpDbMappingDeduplicatesAndSorts(): void
    {
        // 31 -> 18,21 / 21 -> 21 / 16 -> 16: dedupliziert und sortiert
        $this->t->assertEquals([16, 18, 21], WebhookDispatcher::mapCategoriesToAbuseIpDb([31, 21, 16]));
    }

    public function testAbuseIpDbMappingFallsBackToWebAppAttack(): void
    {
        $this->t->assertEquals([21], WebhookDispatcher::mapCategoriesToAbuseIpDb([999]));
    }

    // --- Flache Felder + Template-Rendering ---

    public function testBuildFieldsAggregatesMultipleDetections(): void
    {
        $request = $this->createRequest([
            'uri'    => '/wp-login.php',
            'method' => 'POST',
            'ip'     => '203.0.113.50',
        ]);
        $request->setIp('203.0.113.50');

        $results = [
            new DetectionResult([16], 'SQLi found', 85, 'SqlInjection'),
            new DetectionResult([18, 31], 'Brute force', 60, 'BruteForce'),
        ];

        $fields = $this->dispatcher->buildFields($request, $results);

        $this->t->assertEquals('203.0.113.50', $fields['ip']);
        $this->t->assertEquals('16,18,31', $fields['categories']);
        $this->t->assertEquals('16,18,21', $fields['abuseipdb_categories']);
        $this->t->assertEquals('85', $fields['severity']);
        $this->t->assertEquals('BruteForce,SqlInjection', $fields['analyzers']);
        $this->t->assertContains('[SqlInjection] SQLi found', $fields['comment']);
        $this->t->assertContains('[BruteForce] Brute force', $fields['comment']);
    }

    public function testRenderTemplateReplacesPlaceholders(): void
    {
        $fields = ['ip' => '203.0.113.50', 'comment' => 'a b&c'];
        $rendered = WebhookDispatcher::renderTemplate(
            'ip={{ip_url}}&comment={{comment_url}} raw={{ip}} json={{comment_json}}',
            $fields
        );
        $this->t->assertEquals('ip=203.0.113.50&comment=a%20b%26c raw=203.0.113.50 json=a b&c', $rendered);
    }

    public function testRenderTemplateLeavesUnknownPlaceholders(): void
    {
        $rendered = WebhookDispatcher::renderTemplate('x={{unknown}}', ['ip' => '1.2.3.4']);
        $this->t->assertEquals('x={{unknown}}', $rendered);
    }

    // --- Custom-Header-Parsing ---

    public function testParseHeaderLines(): void
    {
        $headers = WebhookDispatcher::parseHeaderLines("Key: abc123\nAccept: application/json\n\ninvalid-line\nX-Foo:bar");
        $this->t->assertEquals(['Key: abc123', 'Accept: application/json', 'X-Foo: bar'], $headers);
    }

    public function testParseHeaderLinesStripsCrlfInjection(): void
    {
        $headers = WebhookDispatcher::parseHeaderLines("Key: abc\r\nEvil: injected");
        $this->t->assertEquals(['Key: abc', 'Evil: injected'], $headers);
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
