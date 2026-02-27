<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Persistence;

use ReportedIp\Honeypot\Network\CidrMatcher;

/**
 * IP whitelist manager.
 *
 * Manages a list of IPs that should not be reported to the API.
 * Supports both exact IP addresses and CIDR ranges.
 */
final class Whitelist
{
    public function __construct(private readonly Database $db) {}

    /**
     * Check if an IP is whitelisted (exact match or CIDR membership).
     */
    public function isWhitelisted(string $ip): bool
    {
        $entries = $this->getActive();

        foreach ($entries as $entry) {
            $addr = $entry['ip_address'];

            // CIDR range check
            if (str_contains($addr, '/')) {
                if (CidrMatcher::matches($ip, $addr)) {
                    return true;
                }
            } elseif ($addr === $ip) {
                return true;
            }
        }

        return false;
    }

    /**
     * Add an IP or CIDR range to the whitelist.
     */
    public function add(string $ip, string $description = ''): void
    {
        // Check if already exists
        $existing = $this->db->query(
            'SELECT id, is_active FROM honeypot_whitelist WHERE ip_address = ?',
            [$ip]
        )->fetch();

        if ($existing) {
            // Reactivate if deactivated
            $this->db->query(
                'UPDATE honeypot_whitelist SET is_active = 1, description = ? WHERE ip_address = ?',
                [$description, $ip]
            );
            return;
        }

        $this->db->insert('honeypot_whitelist', [
            'ip_address'  => $ip,
            'description' => $description,
        ]);
    }

    /**
     * Remove an IP from the whitelist (deactivates it).
     */
    public function remove(string $ip): void
    {
        $this->db->query(
            'UPDATE honeypot_whitelist SET is_active = 0 WHERE ip_address = ?',
            [$ip]
        );
    }

    /**
     * Get all whitelist entries (active and inactive).
     *
     * @return array<int, array<string, mixed>>
     */
    public function getAll(): array
    {
        $stmt = $this->db->query(
            'SELECT * FROM honeypot_whitelist ORDER BY added_date DESC'
        );
        return $stmt->fetchAll();
    }

    /**
     * Check if a specific IP entry is active.
     */
    public function isActive(string $ip): bool
    {
        $result = $this->db->query(
            'SELECT is_active FROM honeypot_whitelist WHERE ip_address = ?',
            [$ip]
        )->fetch();

        return $result !== false && (int) $result['is_active'] === 1;
    }

    /**
     * Get all active whitelist entries.
     *
     * @return array<int, array<string, mixed>>
     */
    private function getActive(): array
    {
        $stmt = $this->db->query(
            'SELECT ip_address FROM honeypot_whitelist WHERE is_active = 1'
        );
        return $stmt->fetchAll();
    }
}
