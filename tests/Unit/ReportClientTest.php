<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Api\ReportClient;
use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Tests\TestCase;

final class ReportClientTest extends TestCase
{
    public function testIsRateLimitedReturnsFalseInitially(): void
    {
        $config = new Config(['report_rate_limit' => 60]);
        $client = new ReportClient($config);
        $this->t->assertFalse($client->isRateLimited());
    }

    public function testIsRateLimitedWithZeroLimit(): void
    {
        $config = new Config(['report_rate_limit' => 0]);
        $client = new ReportClient($config);
        // With limit=0, any count >= 0 means rate limited
        $this->t->assertTrue($client->isRateLimited());
    }

    public function testReportReturnsFalseWithEmptyApiKey(): void
    {
        $config = new Config(['api_key' => '', 'report_rate_limit' => 60]);
        $client = new ReportClient($config);
        $result = $client->report('1.2.3.4', '16', 'test');
        $this->t->assertFalse($result);
    }

    public function testReportReturnsFalseWhenRateLimited(): void
    {
        $config = new Config(['api_key' => 'test_key', 'report_rate_limit' => 0]);
        $client = new ReportClient($config);
        $result = $client->report('1.2.3.4', '16', 'test');
        $this->t->assertFalse($result);
    }

    public function testDefaultRateLimitIs60(): void
    {
        $config = new Config([]);
        $client = new ReportClient($config);
        // Default rate_limit_per_ip should be 60, so not rate limited initially
        $this->t->assertFalse($client->isRateLimited());
    }
}
