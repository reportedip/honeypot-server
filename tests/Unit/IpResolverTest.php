<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Network\IpResolver;
use ReportedIp\Honeypot\Tests\TestCase;

final class IpResolverTest extends TestCase
{
    public function testFallbackToRemoteAddr(): void
    {
        $config = new Config([]);
        $resolver = new IpResolver($config);
        $request = $this->createRequest(['ip' => '203.0.113.50']);
        $ip = $resolver->resolve($request);
        $this->t->assertEquals('203.0.113.50', $ip);
    }

    public function testCfConnectingIpFromCloudflareRange(): void
    {
        $config = new Config([]);
        $resolver = new IpResolver($config);

        // 173.245.48.1 is in the Cloudflare range 173.245.48.0/20
        $request = $this->createRequest([
            'ip'      => '173.245.48.1',
            'headers' => ['Cf-Connecting-Ip' => '85.10.20.30'],
        ]);
        $ip = $resolver->resolve($request);
        $this->t->assertEquals('85.10.20.30', $ip);
    }

    public function testCfConnectingIpIgnoredFromNonCloudflare(): void
    {
        $config = new Config([]);
        $resolver = new IpResolver($config);

        $request = $this->createRequest([
            'ip'      => '8.8.8.8',
            'headers' => ['Cf-Connecting-Ip' => '85.10.20.30'],
        ]);
        $ip = $resolver->resolve($request);
        $this->t->assertEquals('8.8.8.8', $ip);
    }

    public function testXForwardedForFromTrustedProxy(): void
    {
        // Use Cloudflare range as trusted proxy (default config)
        $config = new Config([]);
        $resolver = new IpResolver($config);

        $request = $this->createRequest([
            'ip'      => '104.16.0.1', // Cloudflare range
            'headers' => ['X-Forwarded-For' => '93.184.216.34, 104.16.0.1'],
        ]);
        $ip = $resolver->resolve($request);
        $this->t->assertEquals('93.184.216.34', $ip);
    }

    public function testXForwardedForIgnoredFromUntrustedProxy(): void
    {
        $config = new Config([]);
        $resolver = new IpResolver($config);

        $request = $this->createRequest([
            'ip'      => '1.2.3.4',
            'headers' => ['X-Forwarded-For' => '10.0.0.1'],
        ]);
        $ip = $resolver->resolve($request);
        $this->t->assertEquals('1.2.3.4', $ip);
    }

    public function testXRealIpFromTrustedProxy(): void
    {
        $config = new Config([]);
        $resolver = new IpResolver($config);

        $request = $this->createRequest([
            'ip'      => '162.158.0.1', // Cloudflare range
            'headers' => ['X-Real-Ip' => '198.51.100.25'],
        ]);
        $ip = $resolver->resolve($request);
        $this->t->assertEquals('198.51.100.25', $ip);
    }

    public function testFallsBackToZerosForInvalidRemoteAddr(): void
    {
        $config = new Config([]);
        $resolver = new IpResolver($config);

        $server = ['REQUEST_URI' => '/', 'REQUEST_METHOD' => 'GET', 'REMOTE_ADDR' => 'not-an-ip'];
        $request = new \ReportedIp\Honeypot\Core\Request($server);
        $ip = $resolver->resolve($request);
        $this->t->assertEquals('0.0.0.0', $ip);
    }

    public function testCustomTrustedProxies(): void
    {
        $config = new Config(['trusted_proxies' => ['10.0.0.0/8']]);
        $resolver = new IpResolver($config);

        $request = $this->createRequest([
            'ip'      => '10.0.0.1',
            'headers' => ['X-Forwarded-For' => '203.0.113.100'],
        ]);
        $ip = $resolver->resolve($request);
        $this->t->assertEquals('203.0.113.100', $ip);
    }
}
