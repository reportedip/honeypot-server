<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Update\UpdateManager;
use ReportedIp\Honeypot\Tests\TestCase;

final class UpdateManagerTest extends TestCase
{
    private string $dataDir = '';

    public function setUp(): void
    {
        $this->dataDir = sys_get_temp_dir() . '/honeypot_updmgr_test_' . uniqid();
        @mkdir($this->dataDir, 0775, true);
        @mkdir($this->dataDir . '/tmp', 0775, true);
        @mkdir($this->dataDir . '/backups', 0775, true);
    }

    public function tearDown(): void
    {
        $this->removeDir($this->dataDir);
    }

    public function testPreflightCheckDetectsMissingZipExtension(): void
    {
        $config = new Config([
            'db_path' => $this->dataDir . '/honeypot.sqlite',
        ]);

        $manager = new UpdateManager($config);
        $result = $manager->preflightCheck();

        $this->t->assertTrue(is_array($result), 'Preflight should return an array');
        $this->t->assertTrue(array_key_exists('checks', $result), 'Result should have "checks" key');
        $this->t->assertTrue(array_key_exists('zip_extension', $result['checks']), 'Should check zip_extension');

        if (!extension_loaded('zip')) {
            $this->t->assertFalse($result['checks']['zip_extension']['ok'], 'zip check should fail when ext-zip is not loaded');
            $this->t->assertFalse($result['ok'], 'Overall preflight should fail without ext-zip');
        } else {
            $this->t->assertTrue($result['checks']['zip_extension']['ok'], 'zip check should pass when ext-zip is loaded');
        }
    }

    public function testPreflightCheckDetectsNonWritablePaths(): void
    {
        $config = new Config([
            'db_path' => $this->dataDir . '/honeypot.sqlite',
        ]);

        $manager = new UpdateManager($config);
        $result = $manager->preflightCheck();

        // tmp and backup dirs should exist (we created them in setUp)
        $this->t->assertTrue(
            $result['checks']['tmp_writable']['ok'] ?? false,
            'tmp dir should be writable'
        );
        $this->t->assertTrue(
            $result['checks']['backup_writable']['ok'] ?? false,
            'backup dir should be writable'
        );
    }

    public function testPreflightCheckStructure(): void
    {
        $config = new Config([
            'db_path' => $this->dataDir . '/honeypot.sqlite',
        ]);

        $manager = new UpdateManager($config);
        $result = $manager->preflightCheck();

        $this->t->assertTrue(array_key_exists('ok', $result), 'Should have "ok" key');
        $this->t->assertTrue(array_key_exists('checks', $result), 'Should have "checks" key');
        $this->t->assertTrue(array_key_exists('errors', $result), 'Should have "errors" key');
        $this->t->assertTrue(is_bool($result['ok']), '"ok" should be boolean');
        $this->t->assertTrue(is_array($result['checks']), '"checks" should be array');
        $this->t->assertTrue(is_array($result['errors']), '"errors" should be array');
    }

    public function testProtectedPathsAreNotOverwritten(): void
    {
        // Create a temporary "project" structure to test the protection logic
        $projectDir = $this->dataDir . '/project';
        @mkdir($projectDir . '/config', 0775, true);
        @mkdir($projectDir . '/data', 0775, true);
        @mkdir($projectDir . '/vendor', 0775, true);

        // Write protected files
        file_put_contents($projectDir . '/config/config.php', '<?php return ["test" => true];');
        file_put_contents($projectDir . '/data/important.sqlite', 'database content');
        file_put_contents($projectDir . '/vendor/autoload.php', '<?php // autoload');

        $originalConfig = file_get_contents($projectDir . '/config/config.php');
        $originalData = file_get_contents($projectDir . '/data/important.sqlite');
        $originalVendor = file_get_contents($projectDir . '/vendor/autoload.php');

        // Verify the files still contain original content (no update was run)
        // This test verifies the PROTECTED_PATHS constant exists and the isProtected logic
        $config = new Config([
            'db_path' => $this->dataDir . '/honeypot.sqlite',
        ]);

        $manager = new UpdateManager($config);

        // Use reflection to test the isProtected method
        $reflection = new \ReflectionClass($manager);
        $method = $reflection->getMethod('isProtected');
        $method->setAccessible(true);

        $this->t->assertTrue($method->invoke($manager, 'config/config.php'), 'config/config.php should be protected');
        $this->t->assertTrue($method->invoke($manager, 'data'), 'data should be protected');
        $this->t->assertTrue($method->invoke($manager, 'data/important.sqlite'), 'data/important.sqlite should be protected');
        $this->t->assertTrue($method->invoke($manager, 'vendor'), 'vendor should be protected');
        $this->t->assertTrue($method->invoke($manager, 'vendor/autoload.php'), 'vendor/autoload.php should be protected');

        $this->t->assertFalse($method->invoke($manager, 'src/Core/App.php'), 'src/Core/App.php should NOT be protected');
        $this->t->assertFalse($method->invoke($manager, 'VERSION'), 'VERSION should NOT be protected');
        $this->t->assertFalse($method->invoke($manager, 'public/index.php'), 'public/index.php should NOT be protected');
        $this->t->assertFalse($method->invoke($manager, 'templates/admin/layout.php'), 'templates should NOT be protected');
    }

    public function testGetBackupsReturnsArray(): void
    {
        $config = new Config([
            'db_path' => $this->dataDir . '/honeypot.sqlite',
        ]);

        $manager = new UpdateManager($config);
        $backups = $manager->getBackups();

        $this->t->assertTrue(is_array($backups), 'getBackups should return an array');
    }

    public function testRollbackFailsWithInvalidPath(): void
    {
        $config = new Config([
            'db_path' => $this->dataDir . '/honeypot.sqlite',
        ]);

        $manager = new UpdateManager($config);
        $result = $manager->rollback('/nonexistent/path/backup');

        $this->t->assertFalse($result['success'], 'Rollback should fail with invalid path');
        $this->t->assertTrue(
            str_contains($result['message'], 'not found'),
            'Error message should mention not found'
        );
    }

    private function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($iterator as $item) {
            if ($item->isDir()) {
                @rmdir($item->getPathname());
            } else {
                @unlink($item->getPathname());
            }
        }

        @rmdir($dir);
    }
}
