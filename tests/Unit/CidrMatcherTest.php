<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Network\CidrMatcher;
use ReportedIp\Honeypot\Tests\TestCase;

final class CidrMatcherTest extends TestCase
{
    public function testMatchesExactIp(): void
    {
        $this->t->assertTrue(CidrMatcher::matches('192.168.1.1', '192.168.1.1'));
        $this->t->assertFalse(CidrMatcher::matches('192.168.1.2', '192.168.1.1'));
    }

    public function testMatchesCidr24(): void
    {
        $this->t->assertTrue(CidrMatcher::matches('192.168.1.0', '192.168.1.0/24'));
        $this->t->assertTrue(CidrMatcher::matches('192.168.1.255', '192.168.1.0/24'));
        $this->t->assertTrue(CidrMatcher::matches('192.168.1.100', '192.168.1.0/24'));
        $this->t->assertFalse(CidrMatcher::matches('192.168.2.1', '192.168.1.0/24'));
    }

    public function testMatchesCidr16(): void
    {
        $this->t->assertTrue(CidrMatcher::matches('10.0.0.1', '10.0.0.0/16'));
        $this->t->assertTrue(CidrMatcher::matches('10.0.255.255', '10.0.0.0/16'));
        $this->t->assertFalse(CidrMatcher::matches('10.1.0.1', '10.0.0.0/16'));
    }

    public function testMatchesCidr8(): void
    {
        $this->t->assertTrue(CidrMatcher::matches('10.255.255.255', '10.0.0.0/8'));
        $this->t->assertFalse(CidrMatcher::matches('11.0.0.1', '10.0.0.0/8'));
    }

    public function testMatchesCidr32(): void
    {
        $this->t->assertTrue(CidrMatcher::matches('1.2.3.4', '1.2.3.4/32'));
        $this->t->assertFalse(CidrMatcher::matches('1.2.3.5', '1.2.3.4/32'));
    }

    public function testReturnsFalseForInvalidIp(): void
    {
        $this->t->assertFalse(CidrMatcher::matches('not-an-ip', '10.0.0.0/8'));
    }

    public function testReturnsFalseForInvalidCidr(): void
    {
        $this->t->assertFalse(CidrMatcher::matches('10.0.0.1', 'invalid/8'));
    }

    public function testMatchesAnyFindsMatch(): void
    {
        $cidrs = ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12'];
        $this->t->assertTrue(CidrMatcher::matchesAny('10.20.30.40', $cidrs));
        $this->t->assertTrue(CidrMatcher::matchesAny('192.168.50.1', $cidrs));
        $this->t->assertTrue(CidrMatcher::matchesAny('172.20.0.1', $cidrs));
    }

    public function testMatchesAnyReturnsFalse(): void
    {
        $cidrs = ['192.168.0.0/16', '10.0.0.0/8'];
        $this->t->assertFalse(CidrMatcher::matchesAny('8.8.8.8', $cidrs));
    }

    public function testMatchesAnyWithEmptyList(): void
    {
        $this->t->assertFalse(CidrMatcher::matchesAny('1.2.3.4', []));
    }

    public function testCloudflareRange(): void
    {
        $this->t->assertTrue(CidrMatcher::matches('173.245.48.1', '173.245.48.0/20'));
        $this->t->assertTrue(CidrMatcher::matches('104.16.0.1', '104.16.0.0/13'));
    }
}
