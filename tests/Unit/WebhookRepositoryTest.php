<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Persistence\WebhookRepository;
use ReportedIp\Honeypot\Tests\TestCase;

final class WebhookRepositoryTest extends TestCase
{
    private string $dbPath;
    private Database $db;
    private WebhookRepository $repo;

    public function setUp(): void
    {
        $this->dbPath = sys_get_temp_dir() . '/honeypot_webhook_test_' . uniqid() . '.sqlite';
        $this->db = new Database($this->dbPath);
        $this->db->initialize();
        $this->repo = new WebhookRepository($this->db);
    }

    public function tearDown(): void
    {
        @unlink($this->dbPath);
    }

    public function testAddAndGetById(): void
    {
        $id = $this->repo->add([
            'name'       => 'My SIEM',
            'url'        => 'https://siem.example.com/hook',
            'secret'     => 's3cret',
            'categories' => '16,18',
            'analyzers'  => 'SqlInjection',
        ]);

        $this->t->assertTrue($id > 0);

        $webhook = $this->repo->getById($id);
        $this->t->assertNotNull($webhook);
        $this->t->assertEquals('My SIEM', $webhook['name']);
        $this->t->assertEquals('https://siem.example.com/hook', $webhook['url']);
        $this->t->assertEquals('16,18', $webhook['categories']);
        $this->t->assertEquals('SqlInjection', $webhook['analyzers']);
        $this->t->assertEquals(1, (int) $webhook['enabled']);
    }

    public function testAddStoresDeliveryFormatFields(): void
    {
        $id = $this->repo->add([
            'name'          => 'AbuseIPDB',
            'url'           => 'https://api.abuseipdb.com/api/v2/report',
            'headers'       => "Key: my-api-key\nAccept: application/json",
            'body_format'   => 'custom',
            'body_template' => 'ip={{ip_url}}&categories={{abuseipdb_categories}}&comment={{comment_url}}',
        ]);

        $webhook = $this->repo->getById($id);
        $this->t->assertEquals('custom', $webhook['body_format']);
        $this->t->assertContains('Key: my-api-key', $webhook['headers']);
        $this->t->assertContains('{{abuseipdb_categories}}', $webhook['body_template']);
    }

    public function testBodyFormatDefaultsToJson(): void
    {
        $id = $this->repo->add(['name' => 'A', 'url' => 'https://a.example.com/']);
        $webhook = $this->repo->getById($id);
        $this->t->assertEquals('json', $webhook['body_format']);
    }

    public function testGetByIdReturnsNullForUnknown(): void
    {
        $this->t->assertNull($this->repo->getById(999));
    }

    public function testGetAllReturnsAllWebhooks(): void
    {
        $this->repo->add(['name' => 'A', 'url' => 'https://a.example.com/']);
        $this->repo->add(['name' => 'B', 'url' => 'https://b.example.com/']);

        $all = $this->repo->getAll();
        $this->t->assertEquals(2, count($all));
    }

    public function testGetEnabledExcludesDisabled(): void
    {
        $idA = $this->repo->add(['name' => 'A', 'url' => 'https://a.example.com/']);
        $this->repo->add(['name' => 'B', 'url' => 'https://b.example.com/']);

        $this->repo->setEnabled($idA, false);

        $enabled = $this->repo->getEnabled();
        $this->t->assertEquals(1, count($enabled));
        $this->t->assertEquals('B', $enabled[0]['name']);
    }

    public function testUpdate(): void
    {
        $id = $this->repo->add(['name' => 'Old', 'url' => 'https://old.example.com/']);
        $this->repo->update($id, [
            'name'       => 'New',
            'url'        => 'https://new.example.com/',
            'secret'     => 'newsecret',
            'categories' => '21',
            'analyzers'  => '',
        ]);

        $webhook = $this->repo->getById($id);
        $this->t->assertEquals('New', $webhook['name']);
        $this->t->assertEquals('https://new.example.com/', $webhook['url']);
        $this->t->assertEquals('21', $webhook['categories']);
    }

    public function testDelete(): void
    {
        $id = $this->repo->add(['name' => 'Temp', 'url' => 'https://t.example.com/']);
        $this->repo->delete($id);
        $this->t->assertNull($this->repo->getById($id));
    }

    public function testRecordResultSuccess(): void
    {
        $id = $this->repo->add(['name' => 'A', 'url' => 'https://a.example.com/']);
        $this->repo->recordResult($id, true, 'HTTP 200');

        $webhook = $this->repo->getById($id);
        $this->t->assertEquals('HTTP 200', $webhook['last_status']);
        $this->t->assertEquals(0, (int) $webhook['failure_count']);
        $this->t->assertNotNull($webhook['last_triggered_at']);
    }

    public function testRecordResultFailureIncrementsCounter(): void
    {
        $id = $this->repo->add(['name' => 'A', 'url' => 'https://a.example.com/']);
        $this->repo->recordResult($id, false, 'HTTP 500');
        $this->repo->recordResult($id, false, 'Timeout');

        $webhook = $this->repo->getById($id);
        $this->t->assertEquals(2, (int) $webhook['failure_count']);
        $this->t->assertEquals('Timeout', $webhook['last_status']);
    }

    public function testSuccessResetsFailureCounter(): void
    {
        $id = $this->repo->add(['name' => 'A', 'url' => 'https://a.example.com/']);
        $this->repo->recordResult($id, false, 'HTTP 500');
        $this->repo->recordResult($id, true, 'HTTP 200');

        $webhook = $this->repo->getById($id);
        $this->t->assertEquals(0, (int) $webhook['failure_count']);
    }
}
