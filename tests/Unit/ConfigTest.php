<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Tests\TestCase;

final class ConfigTest extends TestCase
{
    public function testGetReturnsValueForExistingKey(): void
    {
        $config = new Config(['api_key' => 'abc123', 'debug' => true]);
        $this->t->assertEquals('abc123', $config->get('api_key'));
    }

    public function testGetReturnsDefaultForMissingKey(): void
    {
        $config = new Config([]);
        $this->t->assertEquals('fallback', $config->get('missing_key', 'fallback'));
    }

    public function testGetReturnsNullWhenNoDefault(): void
    {
        $config = new Config([]);
        $this->t->assertNull($config->get('nonexistent'));
    }

    public function testHasReturnsTrueForExistingKey(): void
    {
        $config = new Config(['name' => 'test']);
        $this->t->assertTrue($config->has('name'));
    }

    public function testHasReturnsFalseForMissingKey(): void
    {
        $config = new Config(['name' => 'test']);
        $this->t->assertFalse($config->has('other'));
    }

    public function testHasReturnsTrueForNullValue(): void
    {
        $config = new Config(['key' => null]);
        $this->t->assertTrue($config->has('key'));
    }

    public function testAllReturnsEntireArray(): void
    {
        $data = ['a' => 1, 'b' => 2, 'c' => 3];
        $config = new Config($data);
        $this->t->assertEquals($data, $config->all());
    }

    public function testFromFileThrowsOnMissingFile(): void
    {
        $threw = false;
        try {
            Config::fromFile('/nonexistent/path/config.php');
        } catch (\RuntimeException $e) {
            $threw = true;
            $this->t->assertContains('not found', $e->getMessage());
        }
        $this->t->assertTrue($threw, 'Expected RuntimeException for missing file');
    }

    public function testFromFileLoadsValidConfig(): void
    {
        $tmpFile = sys_get_temp_dir() . '/honeypot_test_config_' . uniqid() . '.php';
        file_put_contents($tmpFile, '<?php return ["api_key" => "test123"];');

        try {
            $config = Config::fromFile($tmpFile);
            $this->t->assertEquals('test123', $config->get('api_key'));
        } finally {
            @unlink($tmpFile);
        }
    }

    public function testFromFileThrowsOnNonArrayReturn(): void
    {
        $tmpFile = sys_get_temp_dir() . '/honeypot_test_config_bad_' . uniqid() . '.php';
        file_put_contents($tmpFile, '<?php return "not an array";');

        $threw = false;
        try {
            Config::fromFile($tmpFile);
        } catch (\RuntimeException $e) {
            $threw = true;
            $this->t->assertContains('must return an array', $e->getMessage());
        } finally {
            @unlink($tmpFile);
        }
        $this->t->assertTrue($threw, 'Expected RuntimeException for non-array config');
    }
}
