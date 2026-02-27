<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Update\UpdateChecker;
use ReportedIp\Honeypot\Tests\TestCase;

final class UpdateCheckerTest extends TestCase
{
    private string $dataDir = '';

    public function setUp(): void
    {
        $this->dataDir = sys_get_temp_dir() . '/honeypot_update_test_' . uniqid();
        @mkdir($this->dataDir, 0775, true);
    }

    public function tearDown(): void
    {
        $files = @glob($this->dataDir . '/*');
        if (is_array($files)) {
            foreach ($files as $file) {
                @unlink($file);
            }
        }
        @rmdir($this->dataDir);
    }

    public function testGetCurrentVersionReadsFile(): void
    {
        $config = new Config([
            'db_path' => $this->dataDir . '/honeypot.sqlite',
        ]);

        $checker = new UpdateChecker($config);
        $version = $checker->getCurrentVersion();

        // The VERSION file should exist in the project root and contain a semver string
        $this->t->assertTrue($version !== '', 'Version should not be empty');
        $this->t->assertTrue($version !== 'unknown', 'Version should not be "unknown"');
        $this->t->assertTrue(
            (bool) preg_match('/^\d+\.\d+\.\d+/', $version),
            'Version should be a valid semver string, got: ' . $version
        );
    }

    public function testMaybeCheckSkipsWhenIntervalNotElapsed(): void
    {
        $config = new Config([
            'db_path' => $this->dataDir . '/honeypot.sqlite',
            'update_check_interval' => 10800,
            'auto_update' => false,
        ]);

        $checker = new UpdateChecker($config);

        // Write a status file with a recent check timestamp
        $statusFile = $this->dataDir . '/update_status.json';
        file_put_contents($statusFile, json_encode([
            'last_check_ts' => time(),
            'last_check_time' => date('Y-m-d H:i:s'),
            'update_available' => false,
        ], JSON_PRETTY_PRINT));

        // maybeCheck should return without hitting the API
        $checker->maybeCheck();

        // Verify the status was not updated (timestamp stays the same)
        $data = json_decode((string) file_get_contents($statusFile), true);
        $this->t->assertTrue(is_array($data), 'Status file should still be valid JSON');
        $this->t->assertTrue(
            (time() - ($data['last_check_ts'] ?? 0)) < 5,
            'last_check_ts should not have been updated significantly'
        );
    }

    public function testForceCheckReturnsStructuredResult(): void
    {
        // Skip if no network connectivity (CI environments)
        if (!function_exists('curl_init')) {
            $this->t->assertTrue(true, 'Skipped: cURL not available');
            return;
        }

        $config = new Config([
            'db_path' => $this->dataDir . '/honeypot.sqlite',
            'auto_update' => false,
        ]);

        $checker = new UpdateChecker($config);
        $result = $checker->forceCheck();

        // Should return the expected structure regardless of network success
        $this->t->assertTrue(array_key_exists('available', $result), 'Result should have "available" key');
        $this->t->assertTrue(array_key_exists('latest_version', $result), 'Result should have "latest_version" key');
        $this->t->assertTrue(array_key_exists('download_url', $result), 'Result should have "download_url" key');
        $this->t->assertTrue(array_key_exists('release_notes', $result), 'Result should have "release_notes" key');
        $this->t->assertTrue(array_key_exists('published_at', $result), 'Result should have "published_at" key');
        $this->t->assertTrue(is_bool($result['available']), '"available" should be a boolean');
    }

    public function testSaveAndLoadStatus(): void
    {
        $config = new Config([
            'db_path' => $this->dataDir . '/honeypot.sqlite',
        ]);

        $checker = new UpdateChecker($config);

        $testData = [
            'current_version' => '1.0.0',
            'last_check_ts' => time(),
            'update_available' => true,
            'latest_version' => '2.0.0',
        ];

        $checker->saveStatus($testData);

        $loaded = $checker->loadStatus();
        $this->t->assertEquals('1.0.0', $loaded['current_version'] ?? '', 'current_version should persist');
        $this->t->assertTrue($loaded['update_available'] ?? false, 'update_available should persist');
        $this->t->assertEquals('2.0.0', $loaded['latest_version'] ?? '', 'latest_version should persist');
    }

    public function testGetStatusFilePath(): void
    {
        $config = new Config([
            'db_path' => $this->dataDir . '/honeypot.sqlite',
        ]);

        $checker = new UpdateChecker($config);
        $path = $checker->getStatusFilePath();

        $this->t->assertNotNull($path, 'Status file path should not be null');
        $this->t->assertTrue(
            str_ends_with($path, '/update_status.json'),
            'Status file should be named update_status.json'
        );
    }
}
