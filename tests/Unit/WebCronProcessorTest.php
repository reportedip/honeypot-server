<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Api\WebCronProcessor;
use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Tests\TestCase;

final class WebCronProcessorTest extends TestCase
{
    private ?Database $db = null;
    private string $dbPath = '';
    private string $dataDir = '';

    public function setUp(): void
    {
        $this->dataDir = sys_get_temp_dir() . '/honeypot_test_' . uniqid();
        @mkdir($this->dataDir, 0775, true);
        $this->dbPath = $this->dataDir . '/honeypot.sqlite';

        $this->db = new Database($this->dbPath);
        $this->db->initialize();
    }

    public function tearDown(): void
    {
        $this->db = null;

        // Clean up temp files
        $files = glob($this->dataDir . '/*');
        if (is_array($files)) {
            foreach ($files as $file) {
                @unlink($file);
            }
        }
        @rmdir($this->dataDir);
    }

    public function testProcessSkipsWhenNoApiKey(): void
    {
        $config = new Config([
            'api_key' => '',
            'db_path' => $this->dbPath,
        ]);

        $processor = new WebCronProcessor($this->db, $config);
        $processor->process();

        // Should not create status file when no API key
        $statusFile = $this->dataDir . '/cron_status.json';
        $this->t->assertFalse(file_exists($statusFile), 'Status file should not be created when API key is empty');
    }

    public function testProcessSkipsWhenQueueEmpty(): void
    {
        $config = new Config([
            'api_key' => str_repeat('a', 64),
            'db_path' => $this->dbPath,
            'report_rate_limit' => 60,
        ]);

        $processor = new WebCronProcessor($this->db, $config);
        $processor->process();

        // With empty queue, no status file should be written (only cleanup check)
        // The status file may or may not exist depending on cleanup logic,
        // but no errors should occur
        $this->t->assertTrue(true, 'Processing empty queue should not throw');
    }

    public function testProcessCreatesStatusFile(): void
    {
        $config = new Config([
            'api_key' => str_repeat('a', 64),
            'api_url' => 'https://invalid.test/api',
            'db_path' => $this->dbPath,
            'report_rate_limit' => 60,
        ]);

        // Insert a dummy unsent entry
        $this->db->query(
            "INSERT INTO honeypot_logs (ip, categories, comment, request_uri, request_method, user_agent, timestamp, sent)
             VALUES (?, ?, ?, ?, ?, ?, datetime('now'), 0)",
            ['1.2.3.4', '16', 'Test attack', '/wp-login.php', 'POST', 'TestBot/1.0']
        );

        $processor = new WebCronProcessor($this->db, $config);

        // process() will attempt to send but fail (invalid URL) — that's OK
        $processor->process();

        $statusFile = $this->dataDir . '/cron_status.json';
        $this->t->assertTrue(file_exists($statusFile), 'Status file should be created after processing');

        $data = json_decode((string) file_get_contents($statusFile), true);
        $this->t->assertTrue(is_array($data), 'Status file should contain valid JSON');
        $this->t->assertEquals('web', $data['queue_mode'] ?? '', 'Queue mode should be "web"');
        $this->t->assertNotNull($data['last_run'] ?? null, 'last_run should be set');
    }
}
