<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Network;

use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Core\Request;

/**
 * Resolves the real client IP address.
 *
 * Handles proxy headers (Cloudflare, X-Forwarded-For, X-Real-IP)
 * and validates that proxy headers are only trusted from known ranges.
 */
final class IpResolver
{
    /** @var string[] Cloudflare IPv4 ranges */
    private const CLOUDFLARE_RANGES = [
        '173.245.48.0/20',
        '103.21.244.0/22',
        '103.22.200.0/22',
        '103.31.4.0/22',
        '141.101.64.0/18',
        '108.162.192.0/18',
        '190.93.240.0/20',
        '188.114.96.0/20',
        '197.234.240.0/22',
        '198.41.128.0/17',
        '162.158.0.0/15',
        '104.16.0.0/13',
        '104.24.0.0/14',
        '172.64.0.0/13',
        '131.0.72.0/22',
    ];

    /** @var string[] */
    private readonly array $trustedProxies;

    public function __construct(private readonly Config $config)
    {
        $this->trustedProxies = $config->get('trusted_proxies', self::CLOUDFLARE_RANGES);
    }

    /**
     * Resolve the real client IP from the request.
     */
    public function resolve(Request $request): string
    {
        $remoteAddr = $request->getServerParam('REMOTE_ADDR') ?? '0.0.0.0';

        // 1. Check CF-Connecting-IP (Cloudflare)
        $cfIp = $request->getHeader('Cf-Connecting-Ip');
        if ($cfIp !== null && $this->isCloudflare($remoteAddr)) {
            $cfIp = trim($cfIp);
            if ($this->isValidIp($cfIp)) {
                return $cfIp;
            }
        }

        // 2. Check X-Forwarded-For from trusted proxies
        $xff = $request->getHeader('X-Forwarded-For');
        if ($xff !== null && $this->isTrustedProxy($remoteAddr)) {
            $ips = array_map('trim', explode(',', $xff));
            // The first IP in the chain is the original client
            foreach ($ips as $ip) {
                if ($this->isValidIp($ip) && !$this->isTrustedProxy($ip)) {
                    return $ip;
                }
            }
        }

        // 3. Check X-Real-IP from trusted proxies
        $realIp = $request->getHeader('X-Real-Ip');
        if ($realIp !== null && $this->isTrustedProxy($remoteAddr)) {
            $realIp = trim($realIp);
            if ($this->isValidIp($realIp)) {
                return $realIp;
            }
        }

        // 4. Fall back to REMOTE_ADDR
        if ($this->isValidIp($remoteAddr)) {
            return $remoteAddr;
        }

        return '0.0.0.0';
    }

    /**
     * Check if the given IP is in a Cloudflare range.
     */
    private function isCloudflare(string $ip): bool
    {
        return CidrMatcher::matchesAny($ip, self::CLOUDFLARE_RANGES);
    }

    /**
     * Check if the given IP is a trusted proxy.
     */
    private function isTrustedProxy(string $ip): bool
    {
        return CidrMatcher::matchesAny($ip, $this->trustedProxies);
    }

    /**
     * Validate an IP address format.
     */
    private function isValidIp(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }
}
