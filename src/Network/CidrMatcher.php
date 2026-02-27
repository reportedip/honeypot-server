<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Network;

/**
 * CIDR range matcher for IPv4 and IPv6 addresses.
 */
final class CidrMatcher
{
    /**
     * Check if an IP address falls within a CIDR range.
     */
    public static function matches(string $ip, string $cidr): bool
    {
        if (!str_contains($cidr, '/')) {
            return $ip === $cidr;
        }

        [$subnet, $bits] = explode('/', $cidr, 2);
        $bits = (int) $bits;

        if (filter_var($ip, FILTER_VALIDATE_IP) === false
            || filter_var($subnet, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        $ipBin = inet_pton($ip);
        $subnetBin = inet_pton($subnet);

        if ($ipBin === false || $subnetBin === false) {
            return false;
        }

        // Ensure both addresses are the same family
        if (strlen($ipBin) !== strlen($subnetBin)) {
            return false;
        }

        // Build the mask
        $maxBits = strlen($ipBin) * 8;
        if ($bits < 0 || $bits > $maxBits) {
            return false;
        }

        $mask = str_repeat("\xff", (int) ($bits / 8));
        if ($bits % 8 !== 0) {
            $mask .= chr(0xff << (8 - ($bits % 8)) & 0xff);
        }
        $mask = str_pad($mask, strlen($ipBin), "\x00");

        return ($ipBin & $mask) === ($subnetBin & $mask);
    }

    /**
     * Check if an IP matches any CIDR in a list.
     *
     * @param string[] $cidrs
     */
    public static function matchesAny(string $ip, array $cidrs): bool
    {
        foreach ($cidrs as $cidr) {
            if (self::matches($ip, $cidr)) {
                return true;
            }
        }
        return false;
    }
}
