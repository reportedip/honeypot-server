<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Admin\ThreatIntel;
use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Tests\TestCase;

final class ThreatIntelTest extends TestCase
{
    private string $dbPath;
    private Database $db;
    private ThreatIntel $intel;

    public function setUp(): void
    {
        $this->dbPath = sys_get_temp_dir() . '/honeypot_intel_test_' . uniqid() . '.sqlite';
        $this->db = new Database($this->dbPath);
        $this->db->initialize();
        $this->intel = new ThreatIntel($this->db);
    }

    public function tearDown(): void
    {
        @unlink($this->dbPath);
    }

    public function testSummaryCounts(): void
    {
        $this->db->insert('honeypot_honeytokens', [
            'token' => 'HPt1111111111111111', 'token_type' => 'db_password',
            'issued_to_ip' => '1.1.1.1', 'source_path' => '/.env',
        ]);
        $this->db->insert('honeypot_honeytokens', [
            'token' => 'HPt2222222222222222', 'token_type' => 'aws_secret',
            'issued_to_ip' => '1.1.1.1', 'source_path' => '/.env', 'triggered' => 1,
        ]);
        $this->db->insert('honeypot_captures', [
            'ip' => '2.2.2.2', 'capture_type' => 'webshell_post',
            'content_b64' => base64_encode('id;uname -a'), 'size' => 11,
        ]);

        $summary = $this->intel->getSummary();
        $this->t->assertEquals(2, $summary['tokens_issued']);
        $this->t->assertEquals(1, $summary['tokens_triggered']);
        $this->t->assertEquals(1, $summary['captures']);
        $this->t->assertEquals(11, $summary['capture_bytes']);
    }

    public function testHoneytokensTriggeredFirst(): void
    {
        $this->db->insert('honeypot_honeytokens', [
            'token' => 'HPtaaaaaaaaaaaaaaaa', 'token_type' => 'db_password',
            'issued_to_ip' => '1.1.1.1', 'source_path' => '/.env',
        ]);
        $this->db->insert('honeypot_honeytokens', [
            'token' => 'HPtbbbbbbbbbbbbbbbb', 'token_type' => 'aws_secret',
            'issued_to_ip' => '1.1.1.1', 'source_path' => '/.env',
            'triggered' => 1, 'triggered_by_ip' => '9.9.9.9',
        ]);

        $result = $this->intel->getHoneytokens(1);
        $this->t->assertEquals(2, $result['total']);
        $this->t->assertEquals(1, (int) $result['rows'][0]['triggered']);
    }

    public function testGetCaptureDecodesContent(): void
    {
        $id = $this->db->insert('honeypot_captures', [
            'ip' => '2.2.2.2', 'capture_type' => 'admin_upload',
            'filename' => 'evil.zip', 'content_b64' => base64_encode('PK\x03\x04payload'), 'size' => 12,
        ]);

        $capture = $this->intel->getCapture($id);
        $this->t->assertNotNull($capture);
        $this->t->assertEquals('PK\x03\x04payload', $capture['content']);
    }

    public function testGetCaptureReturnsNullForMissing(): void
    {
        $this->t->assertNull($this->intel->getCapture(99999));
    }

    public function testCaptureListOmitsBlob(): void
    {
        $this->db->insert('honeypot_captures', [
            'ip' => '2.2.2.2', 'capture_type' => 'webshell_post',
            'content_b64' => base64_encode('secret-payload'), 'size' => 14,
        ]);
        $result = $this->intel->getCaptures(1);
        $this->t->assertEquals(1, $result['total']);
        $this->t->assertFalse(isset($result['rows'][0]['content_b64']));
    }
}
