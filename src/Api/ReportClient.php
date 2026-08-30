<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Api;

use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Core\Version;

/**
 * HTTP client for the reportedip.com API.
 *
 * Sends IP abuse reports with automatic rate limiting and exponential
 * backoff on transient failures (429, 5xx, 408/499, connection errors).
 *
 * The backoff state is persisted to disk so it survives between requests
 * and processes — under the web-cron model a fresh client is built on every
 * page visit, so an in-memory-only backoff would never take effect and the
 * server would keep hammering an already overloaded API (retry storm).
 */
final class ReportClient
{
    private const BASE_BACKOFF_SECONDS = 5;
    private const MAX_BACKOFF_SECONDS = 300;

    /**
     * Highest category ID every reportedip.com deployment is known to accept.
     *
     * The API validates each reported ID against its own catalogue and rejects
     * the ENTIRE report with HTTP 400 (`rest_invalid_param`) as soon as one ID
     * is unknown to it — so a single honeypot-only category (59-63, added with
     * the high-interaction traps) used to drop the whole detection. IDs up to
     * this bound have existed since API v2 and are safe as a retry payload.
     */
    private const CORE_CATEGORY_MAX = 58;

    private Config $config;

    /** @var int[] Timestamps of recent requests for rate limiting */
    private array $requestTimestamps = [];

    private int $currentBackoff = 0;
    private int $backoffUntil = 0;

    /** @var string|null Last error message for debugging */
    private ?string $lastError = null;

    /** @var int|null HTTP status code of the most recent API response */
    private ?int $lastHttpCode = null;

    public function __construct(Config $config)
    {
        $this->config = $config;
        $this->loadBackoffState();
        $this->loadRateLimitState();
    }

    /**
     * Get the User-Agent string carrying the current application version.
     */
    public static function getUserAgent(): string
    {
        return 'reportedip-honeypot-server/' . Version::current();
    }

    /**
     * Get the last error message from the most recent report() call.
     */
    public function getLastError(): ?string
    {
        return $this->lastError;
    }

    /**
     * Check if the most recent report() call was permanently rejected
     * by the API (e.g. whitelisted IP). Such entries must not be retried.
     */
    public function wasPermanentlyRejected(): bool
    {
        return $this->lastHttpCode !== null
            && self::isPermanentRejectionCode($this->lastHttpCode);
    }

    /**
     * Detect the API's "unknown category" rejection.
     *
     * WordPress answers a failed `validate_callback` with HTTP 400,
     * `code: rest_invalid_param` and the offending parameter name in the message.
     * Only that exact shape warrants a retry with a reduced payload — an
     * invalid key (403) or a malformed IP must not silently be resent.
     */
    public static function isInvalidCategoryRejection(int $httpCode, string $responseBody): bool
    {
        if ($httpCode !== 400) {
            return false;
        }

        if (stripos($responseBody, 'rest_invalid_param') === false) {
            return false;
        }

        return stripos($responseBody, 'categories') !== false;
    }

    /**
     * Reduce a category list to the IDs every API deployment accepts.
     *
     * Used as the retry payload after an "unknown category" rejection: the
     * detection is still reported, just without the categories this API does
     * not know yet. Returns an empty string when nothing is left — there is
     * then no point in retrying.
     */
    public static function stripUnsupportedCategories(string $categories): string
    {
        $kept = [];

        foreach (explode(',', $categories) as $raw) {
            $raw = trim($raw);

            if ($raw === '' || !ctype_digit($raw)) {
                continue;
            }

            $id = (int) $raw;

            if ($id >= 1 && $id <= self::CORE_CATEGORY_MAX) {
                $kept[] = $id;
            }
        }

        return implode(',', array_unique($kept));
    }

    /**
     * 4xx responses are permanent rejections — retrying the same payload will
     * never succeed — EXCEPT for transient 4xx codes:
     *  - 429 Too Many Requests (rate limited)
     *  - 408 Request Timeout
     *  - 499 Client Closed Request (nginx; a symptom of server overload, not
     *    a payload problem — retrying after a backoff can succeed)
     */
    public static function isPermanentRejectionCode(int $httpCode): bool
    {
        if (self::isTransientFailureCode($httpCode)) {
            return false;
        }

        return $httpCode >= 400 && $httpCode < 500;
    }

    /**
     * Transient failures warrant a backoff-and-retry rather than dropping the
     * report: rate limiting (429), request timeout (408), client-closed (499),
     * any 5xx server error, and connection-level failures (cURL → code 0).
     *
     * These are exactly the codes a retry storm produces when the API is
     * overloaded — backing off on them is what breaks the feedback loop.
     */
    public static function isTransientFailureCode(int $httpCode): bool
    {
        if ($httpCode === 429 || $httpCode === 408 || $httpCode === 499) {
            return true;
        }

        if ($httpCode >= 500 && $httpCode < 600) {
            return true;
        }

        // 0 == cURL/connection error (timeout, connection refused, DNS, …)
        return $httpCode === 0;
    }

    /**
     * Report an IP address to the reportedip.com API.
     *
     * @param string $ip         The IP to report.
     * @param string $categories Comma-separated category IDs.
     * @param string $comment    Description of the detected threat.
     * @return bool True if the report was accepted.
     */
    public function report(string $ip, string $categories, string $comment): bool
    {
        $this->lastError = null;
        $this->lastHttpCode = null;

        if ($this->isRateLimited()) {
            $this->lastError = 'Local rate limit exceeded';
            $this->logApiError($ip, 0, 'Local rate limit exceeded', '');
            return false;
        }

        if ($this->isBackedOff()) {
            $this->lastError = sprintf('Backoff active until %s', date('H:i:s', $this->backoffUntil));
            return false;
        }

        $apiUrl = $this->config->get('api_url', 'https://reportedip.com/wp-json/reportedip/v2/report');
        $apiKey = $this->config->get('api_key', '');

        if (empty($apiKey)) {
            $this->lastError = 'No API key configured';
            $this->logApiError($ip, 0, 'No API key configured', '');
            return false;
        }

        return $this->send($apiUrl, $apiKey, $ip, $categories, $comment, true);
    }

    /**
     * Perform a single report request and evaluate the response.
     *
     * @param bool $allowCategoryRetry Whether an "unknown category" rejection
     *                                 may be retried once without the
     *                                 categories this API does not know.
     */
    private function send(
        string $apiUrl,
        string $apiKey,
        string $ip,
        string $categories,
        string $comment,
        bool $allowCategoryRetry
    ): bool {
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
                'User-Agent: ' . self::getUserAgent(),
                'X-Honeypot-Version: ' . Version::current(),
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

        $this->lastHttpCode = $httpCode;
        $this->trackRequest();

        // Handle cURL errors (timeout, connection refused, …) — the API is
        // unreachable/overloaded, so back off instead of retrying immediately.
        if ($curlError !== '') {
            $this->lastError = sprintf('cURL error: %s', $curlError);
            $this->logApiError($ip, 0, $curlError, '');
            $this->applyBackoff();
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
            $this->resetBackoff();
            return true;
        }

        // An API that does not know one of the reported categories rejects the
        // WHOLE report (HTTP 400, rest_invalid_param) — and the queue treats
        // 4xx as final, so the detection would be lost. Retry once with only
        // the categories every deployment accepts; better a report with fewer
        // categories than none at all.
        if ($allowCategoryRetry && self::isInvalidCategoryRejection($httpCode, (string) $response)) {
            $reduced = self::stripUnsupportedCategories($categories);

            if ($reduced !== '' && $reduced !== $categories && !$this->isRateLimited()) {
                $this->logApiError(
                    $ip,
                    $httpCode,
                    sprintf('Unknown categories rejected, retrying with %s', $reduced),
                    (string) $response
                );

                return $this->send($apiUrl, $apiKey, $ip, $reduced, $comment, false);
            }
        }

        // Log all other errors
        $this->lastError = sprintf('HTTP %d: %s', $httpCode, substr((string) $response, 0, 200));
        $this->logApiError($ip, $httpCode, 'API request failed', (string) $response);

        // Transient server-side failures (5xx, 408, 499) get a backoff so an
        // overloaded API isn't hammered. Permanent 4xx rejections do not —
        // the queue drops those entries instead of retrying.
        if (self::isTransientFailureCode($httpCode)) {
            $this->applyBackoff();
        }

        return false;
    }

    /**
     * Check if the client is currently rate limited (sliding 60s window).
     *
     * Reloads the persisted timestamps first so the cap is enforced globally
     * across all requests/processes, not just within this single client
     * instance (web-cron builds a fresh client on every page visit).
     */
    public function isRateLimited(): bool
    {
        $limit = (int) $this->config->get('report_rate_limit', 60);

        $this->loadRateLimitState();

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
     * Check if the client is in a backoff period after a transient failure.
     *
     * Public so the queue processor can stop a batch early instead of letting
     * every entry fail individually while the API is known to be unavailable.
     */
    public function isBackedOff(): bool
    {
        return $this->backoffUntil > time();
    }

    /**
     * Unix timestamp until which the client is backed off (0 if none active).
     */
    public function getBackoffUntil(): int
    {
        return $this->backoffUntil;
    }

    /**
     * Apply exponential backoff after a transient failure and persist it.
     */
    private function applyBackoff(): void
    {
        if ($this->currentBackoff === 0) {
            $this->currentBackoff = self::BASE_BACKOFF_SECONDS;
        } else {
            $this->currentBackoff = min($this->currentBackoff * 2, self::MAX_BACKOFF_SECONDS);
        }

        $this->backoffUntil = time() + $this->currentBackoff;
        $this->persistBackoffState();
    }

    /**
     * Clear the backoff after a successful request and persist the reset.
     */
    private function resetBackoff(): void
    {
        if ($this->currentBackoff === 0 && $this->backoffUntil === 0) {
            return; // already clear — avoid an unnecessary disk write
        }

        $this->currentBackoff = 0;
        $this->backoffUntil = 0;
        $this->persistBackoffState();
    }

    /**
     * Record a request timestamp for rate limiting.
     *
     * Performs an atomic read-modify-write under an exclusive file lock so
     * concurrent page visits (each with their own client) accumulate into one
     * shared, globally enforced window instead of overwriting each other.
     */
    private function trackRequest(): void
    {
        $now = time();
        $windowStart = $now - 60;

        $file = $this->getRateLimitFilePath();
        if ($file === null) {
            // No persistent store (e.g. unit tests) — in-memory only
            $this->requestTimestamps[] = $now;
            return;
        }

        $fp = @fopen($file, 'c+');
        if ($fp === false) {
            $this->requestTimestamps[] = $now;
            return;
        }

        if (flock($fp, LOCK_EX)) {
            $stored = $this->decodeTimestamps(stream_get_contents($fp) ?: '');
            $stored[] = $now;
            $stored = array_values(array_filter(
                $stored,
                static function (int $ts) use ($windowStart): bool {
                    return $ts >= $windowStart;
                }
            ));
            $this->requestTimestamps = $stored;

            ftruncate($fp, 0);
            rewind($fp);
            fwrite($fp, json_encode(['timestamps' => $stored]));
            fflush($fp);
            flock($fp, LOCK_UN);
        }

        fclose($fp);
    }

    /**
     * Load the persisted rate-limit window so the cap survives across requests.
     */
    private function loadRateLimitState(): void
    {
        $file = $this->getRateLimitFilePath();
        if ($file === null || !is_file($file)) {
            return;
        }

        $this->requestTimestamps = $this->decodeTimestamps(
            (string) @file_get_contents($file)
        );
    }

    /**
     * Decode a JSON rate-limit payload into a list of integer timestamps.
     *
     * @return int[]
     */
    private function decodeTimestamps(string $json): array
    {
        $data = @json_decode($json, true);
        if (is_array($data) && isset($data['timestamps']) && is_array($data['timestamps'])) {
            return array_map('intval', $data['timestamps']);
        }

        return [];
    }

    /**
     * Load the persisted backoff state so it survives across requests/processes.
     */
    private function loadBackoffState(): void
    {
        $file = $this->getBackoffFilePath();
        if ($file === null || !is_file($file)) {
            return;
        }

        $data = @json_decode((string) @file_get_contents($file), true);
        if (!is_array($data)) {
            return;
        }

        $this->backoffUntil = (int) ($data['backoff_until'] ?? 0);
        $this->currentBackoff = (int) ($data['current_backoff'] ?? 0);
    }

    /**
     * Persist the current backoff state to disk.
     */
    private function persistBackoffState(): void
    {
        $file = $this->getBackoffFilePath();
        if ($file === null) {
            return;
        }

        @file_put_contents(
            $file,
            json_encode([
                'backoff_until'   => $this->backoffUntil,
                'current_backoff' => $this->currentBackoff,
                'updated_at'      => date('Y-m-d H:i:s'),
            ], JSON_PRETTY_PRINT),
            LOCK_EX
        );
    }

    /**
     * Get the path to the persisted backoff state file.
     *
     * Returns null when no data directory is configured (e.g. in unit tests),
     * keeping the backoff purely in-memory and the filesystem untouched.
     */
    private function getBackoffFilePath(): ?string
    {
        $dataDir = $this->resolveDataDir();

        return $dataDir === null ? null : $dataDir . '/report_backoff.json';
    }

    /**
     * Get the path to the persisted rate-limit window file.
     */
    private function getRateLimitFilePath(): ?string
    {
        $dataDir = $this->resolveDataDir();

        return $dataDir === null ? null : $dataDir . '/report_ratelimit.json';
    }

    /**
     * Resolve the writable data directory, or null when none is available.
     */
    private function resolveDataDir(): ?string
    {
        $dataDir = (string) $this->config->get('data_dir', '');
        if ($dataDir === '') {
            $dbPath = (string) $this->config->get('db_path', '');
            if ($dbPath === '') {
                return null;
            }
            $dataDir = dirname($dbPath);
        }

        return is_dir($dataDir) ? $dataDir : null;
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
