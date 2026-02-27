<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Core\Cache;
use ReportedIp\Honeypot\Tests\TestCase;

final class CacheTest extends TestCase
{
    private string $cachePath;
    private Cache $cache;

    public function setUp(): void
    {
        $this->cachePath = sys_get_temp_dir() . '/honeypot_cache_test_' . uniqid();
        $this->cache = new Cache($this->cachePath, 3600);
    }

    public function tearDown(): void
    {
        $this->cache->clear();
        @rmdir($this->cachePath);
    }

    public function testSetAndGet(): void
    {
        $this->cache->set('key1', 'value1');
        $this->t->assertEquals('value1', $this->cache->get('key1'));
    }

    public function testGetReturnsNullForMissing(): void
    {
        $this->t->assertNull($this->cache->get('nonexistent'));
    }

    public function testHasReturnsTrueForExistingKey(): void
    {
        $this->cache->set('exists', 'yes');
        $this->t->assertTrue($this->cache->has('exists'));
    }

    public function testHasReturnsFalseForMissingKey(): void
    {
        $this->t->assertFalse($this->cache->has('nope'));
    }

    public function testDelete(): void
    {
        $this->cache->set('del_me', 'data');
        $this->t->assertTrue($this->cache->has('del_me'));
        $this->cache->delete('del_me');
        $this->t->assertFalse($this->cache->has('del_me'));
    }

    public function testClear(): void
    {
        $this->cache->set('a', 1);
        $this->cache->set('b', 2);
        $this->cache->clear();
        $this->t->assertFalse($this->cache->has('a'));
        $this->t->assertFalse($this->cache->has('b'));
    }

    public function testTtlExpiry(): void
    {
        // Set with 1-second TTL
        $this->cache->set('expire_soon', 'data', 1);
        $this->t->assertTrue($this->cache->has('expire_soon'));

        // Wait for expiry
        sleep(2);
        $this->t->assertNull($this->cache->get('expire_soon'));
        $this->t->assertFalse($this->cache->has('expire_soon'));
    }

    public function testStoresArrays(): void
    {
        $data = ['foo' => 'bar', 'nums' => [1, 2, 3]];
        $this->cache->set('arr', $data);
        $this->t->assertEquals($data, $this->cache->get('arr'));
    }

    public function testStoresIntegers(): void
    {
        $this->cache->set('num', 42);
        $this->t->assertEquals(42, $this->cache->get('num'));
    }

    public function testZeroTtlNeverExpires(): void
    {
        $this->cache->set('forever', 'persist', 0);
        $this->t->assertEquals('persist', $this->cache->get('forever'));
    }

    public function testDeleteNonexistentKeyDoesNotError(): void
    {
        $this->cache->delete('phantom');
        $this->t->assertFalse($this->cache->has('phantom'));
    }
}
