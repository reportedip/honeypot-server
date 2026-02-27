<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Api;

use ReportedIp\Honeypot\Core\Config;

/**
 * HTTP client for the reportedip.de API.
 *
 * Sends IP abuse reports with automatic rate limiting and
 * exponential backoff on 429 responses.
 */
final class ReportClient
{
    private const USER_AGENT = 'reportedip-honeypot-server/1.0.0';
    private const BASE_BACKOFF_SECONDS = 5;
    private const MAX_BACKOFF_SECONDS = 300;

    private Config $config;

    /** @var int[] Timestamps of recent requests for rate limiting */
    private array $requestTimestamps = [];

    private int $currentBackoff = 0;
    private int $backoffUntil = 0;

    /** @var string|null Last error message for debugging */
    private ?string $lastError = null;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /**
     * Get the last error message from the most recent report() call.
     */
    public function getLastError(): ?string
    {
        return $this->lastError;
    }

    /**
     * Report an IP address to the reportedip.de API.
     *
     * @param string $ip         The IP to report.
     * @param string $categories Comma-separated category IDs.
     * @param string $comment    Description of the detected threat.
     * @return bool True if the report was accepted.
     */
    public function report(string $ip, string $categories, string $comment): bool
    {
        $this->lastError = null;

        if ($this->isRateLimited()) {
            $this->lastError = 'Local rate limit exceeded';
            $this->logApiError($ip, 0, 'Local rate limit exceeded', '');
            return false;
        }

        if ($this->isBackedOff()) {
            $this->lastError = sprintf('Backoff active until %s', date('H:i:s', $this->backoffUntil));
            return false;
        }

        $apiUrl = $this->config->get('api_url', 'https://reportedip.de/wp-json/reportedip/v2/report');
        $apiKey = $this->config->get('api_key', '');

        if (empty($apiKey)) {
            $this->lastError = 'No API key configured';
            $this->logApiError($ip, 0, 'No API key configured', '');
            return false;
        }

        $postFields = http_build_query([
            'ip'         => $ip,
            'categories' => $categories,
            'comment'    => $comment,
        ]);

        $ch = curl_init();
        if ($ch === false) {
            $this->lastError = 'cURL init failed';
            $this->logApiError($ip, 0, 'cURL init failed', '');
            return false;
        }

        $curlOpts = [
            CURLOPT_URL            => $apiUrl,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $postFields,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_HTTPHEADER     => [
                'X-Key: ' . $apiKey,
                'Content-Type: application/x-www-form-urlencoded',
                'User-Agent: ' . self::USER_AGENT,
            ],
        ];

        // Use bundled CA cert if system CA is unavailable
        $caBundle = $this->config->get('ca_bundle', '');
        if ($caBundle !== '' && file_exists($caBundle)) {
            $curlOpts[CURLOPT_CAINFO] = $caBundle;
        }

        curl_setopt_array($ch, $curlOpts);

        $response = curl_exec($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        $this->trackRequest();

        // Handle cURL errors
        if ($curlError !== '') {
            $this->lastError = sprintf('cURL error: %s', $curlError);
            $this->logApiError($ip, 0, $curlError, '');
            return false;
        }

        // Handle rate limiting from the API
        if ($httpCode === 429) {
            $this->lastError = 'API rate limited (429)';
            $this->logApiError($ip, 429, 'Rate limited by API', (string) $response);
            $this->applyBackoff();
            return false;
        }

        // Reset backoff on successful request
        if ($httpCode >= 200 && $httpCode < 300) {
            $this->currentBackoff = 0;
            $this->backoffUntil = 0;
            return true;
        }

        // Log all other errors
        $this->lastError = sprintf('HTTP %d: %s', $httpCode, substr((string) $response, 0, 200));
        $this->logApiError($ip, $httpCode, 'API request failed', (string) $response);
        return false;
    }

    /**
     * Check if the client is currently rate limited (local limit).
     */
    public function isRateLimited(): bool
    {
        $limit = (int) $this->config->get('report_rate_limit', 60);
        $now = time();
        $windowStart = $now - 60;

        // Prune old timestamps
        $this->requestTimestamps = array_values(array_filter(
            $this->requestTimestamps,
            static function (int $ts) use ($windowStart): bool {
                return $ts >= $windowStart;
            }
        ));

        return count($this->requestTimestamps) >= $limit;
    }

    /**
     * Check if the client is in a backoff period (from 429 response).
     */
    private function isBackedOff(): bool
    {
        return $this->backoffUntil > time();
    }

    /**
     * Apply exponential backoff after a 429 response.
     */
    private function applyBackoff(): void
    {
        if ($this->currentBackoff === 0) {
            $this->currentBackoff = self::BASE_BACKOFF_SECONDS;
        } else {
            $this->currentBackoff = min($this->currentBackoff * 2, self::MAX_BACKOFF_SECONDS);
        }

        $this->backoffUntil = time() + $this->currentBackoff;
    }

    /**
     * Record a request timestamp for local rate limiting.
     */
    private function trackRequest(): void
    {
        $this->requestTimestamps[] = time();
    }

    /**
     * Log an API error to the dedicated error log file.
     */
    private function logApiError(string $ip, int $httpCode, string $error, string $responseBody): void
    {
        $logFile = $this->getErrorLogPath();
        if ($logFile === null) {
            return;
        }

        $responseExcerpt = substr(trim($responseBody), 0, 500);
        $line = sprintf(
            "[%s] IP=%s HTTP=%d Error=%s Response=%s\n",
            date('Y-m-d H:i:s'),
            $ip,
            $httpCode,
            $error,
            $responseExcerpt !== '' ? $responseExcerpt : '(empty)'
        );

        @file_put_contents($logFile, $line, FILE_APPEND | LOCK_EX);
    }

    /**
     * Get the path to the API error log file.
     */
    private function getErrorLogPath(): ?string
    {
        $dataDir = $this->config->get('data_dir', '');
        if ($dataDir === '') {
            // Derive from db_path
            $dbPath = $this->config->get('db_path', '');
            if ($dbPath !== '') {
                $dataDir = dirname($dbPath);
            } else {
                $dataDir = dirname(__DIR__, 2) . '/data';
            }
        }

        if (!is_dir($dataDir)) {
            return null;
        }

        return $dataDir . '/api_errors.log';
    }
}
