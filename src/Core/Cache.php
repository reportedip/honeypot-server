<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Core;

/**
 * File-based TTL cache.
 *
 * Stores cached values as JSON files with expiration metadata.
 */
final class Cache
{
    private string $cachePath;
    private readonly int $defaultTtl;

    public function __construct(string $cachePath, int $defaultTtl = 3600)
    {
        $this->cachePath = rtrim($cachePath, '/\\');
        $this->defaultTtl = $defaultTtl;

        if (!is_dir($this->cachePath)) {
            @mkdir($this->cachePath, 0775, true);
        }
    }

    /**
     * Retrieve a value from the cache.
     *
     * @return mixed Cached value or null if missing/expired.
     */
    public function get(string $key): mixed
    {
        $file = $this->getFilePath($key);

        if (!file_exists($file)) {
            return null;
        }

        $content = file_get_contents($file);
        if ($content === false) {
            return null;
        }

        $entry = json_decode($content, true);
        if (!is_array($entry) || !isset($entry['expires'], $entry['data'])) {
            @unlink($file);
            return null;
        }

        if ($entry['expires'] > 0 && $entry['expires'] < time()) {
            @unlink($file);
            return null;
        }

        return $entry['data'];
    }

    /**
     * Store a value in the cache.
     */
    public function set(string $key, mixed $value, ?int $ttl = null): void
    {
        $ttl = $ttl ?? $this->defaultTtl;
        $expires = $ttl > 0 ? time() + $ttl : 0;

        $entry = [
            'expires' => $expires,
            'data'    => $value,
        ];

        $file = $this->getFilePath($key);
        $json = json_encode($entry, JSON_UNESCAPED_SLASHES);
        if ($json !== false) {
            @file_put_contents($file, $json, LOCK_EX);
        }
    }

    /**
     * Check if a non-expired entry exists for the given key.
     */
    public function has(string $key): bool
    {
        return $this->get($key) !== null;
    }

    /**
     * Delete a cache entry.
     */
    public function delete(string $key): void
    {
        $file = $this->getFilePath($key);
        if (file_exists($file)) {
            @unlink($file);
        }
    }

    /**
     * Clear all cache entries.
     */
    public function clear(): void
    {
        $files = glob($this->cachePath . '/*.cache');
        if ($files !== false) {
            foreach ($files as $file) {
                @unlink($file);
            }
        }
    }

    /**
     * Remove expired cache entries.
     */
    public function cleanup(): void
    {
        $files = glob($this->cachePath . '/*.cache');
        if ($files === false) {
            return;
        }

        $now = time();
        foreach ($files as $file) {
            $content = file_get_contents($file);
            if ($content === false) {
                @unlink($file);
                continue;
            }

            $entry = json_decode($content, true);
            if (!is_array($entry) || !isset($entry['expires'])) {
                @unlink($file);
                continue;
            }

            if ($entry['expires'] > 0 && $entry['expires'] < $now) {
                @unlink($file);
            }
        }
    }

    /**
     * Build the file path for a cache key.
     */
    private function getFilePath(string $key): string
    {
        return $this->cachePath . '/' . md5($key) . '.cache';
    }
}
