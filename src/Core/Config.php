<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Core;

/**
 * Configuration container.
 *
 * Wraps the config array loaded from config/config.php with typed access methods.
 */
final class Config
{
    /**
     * @param array<string, mixed> $config
     */
    public function __construct(
        private readonly array $config,
    ) {}

    /**
     * Load configuration from a PHP file that returns an array.
     */
    public static function fromFile(string $path): self
    {
        if (!file_exists($path) || !is_readable($path)) {
            throw new \RuntimeException(sprintf('Configuration file not found or not readable: %s', $path));
        }

        /** @var array<string, mixed> $config */
        $config = require $path;

        if (!is_array($config)) {
            throw new \RuntimeException('Configuration file must return an array.');
        }

        return new self(self::migrateLegacyDomain($config));
    }

    /**
     * Rewrite api_url entries still pointing at the legacy reportedip.de
     * domain to reportedip.com, so existing installations report to the
     * new domain without requiring a manual config edit.
     *
     * @param array<string, mixed> $config
     * @return array<string, mixed>
     */
    private static function migrateLegacyDomain(array $config): array
    {
        if (isset($config['api_url']) && is_string($config['api_url'])) {
            $config['api_url'] = str_replace(
                ['://www.reportedip.de', '://reportedip.de'],
                ['://www.reportedip.com', '://reportedip.com'],
                $config['api_url']
            );
        }

        return $config;
    }

    /**
     * Get a configuration value by key.
     */
    public function get(string $key, mixed $default = null): mixed
    {
        return $this->config[$key] ?? $default;
    }

    /**
     * Check if a configuration key exists.
     */
    public function has(string $key): bool
    {
        return array_key_exists($key, $this->config);
    }

    /**
     * Get the entire configuration array.
     *
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->config;
    }
}
