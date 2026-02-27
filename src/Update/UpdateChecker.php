<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Update;

use ReportedIp\Honeypot\Core\Config;

/**
 * Checks for new releases via the GitHub Releases API.
 *
 * Uses an interval-gated approach (default 3 hours) to avoid excessive API calls.
 * Stores check results in data/update_status.json.
 */
final class UpdateChecker
{
    private const CHECK_INTERVAL = 10800; // 3 hours
    private const GITHUB_API = 'https://api.github.com/repos/%s/releases/latest';
    private const USER_AGENT = 'reportedip-honeypot-server-updater/1.0';
    private const DEFAULT_REPO = 'reportedip/honeypot-server';
    private const STALE_LOCK_TIMEOUT = 600; // 10 minutes

    private Config $config;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /**
     * Interval-gated check: only hits GitHub API if enough time has elapsed.
     */
    public function maybeCheck(): void
    {
        $status = $this->loadStatus();
        $interval = (int) $this->config->get('update_check_interval', self::CHECK_INTERVAL);
        $lastCheck = (int) ($status['last_check_ts'] ?? 0);

        if ((time() - $lastCheck) < $interval) {
            return;
        }

        $this->forceCheck();
        $this->maybeAutoUpdate();
    }

    /**
     * Immediately check GitHub for the latest release.
     *
     * @return array{available: bool, latest_version: string, download_url: string, release_notes: string, published_at: string}
     */
    public function forceCheck(): array
    {
        $result = [
            'available' => false,
            'latest_version' => '',
            'download_url' => '',
            'release_notes' => '',
            'published_at' => '',
        ];

        $repo = (string) $this->config->get('github_repo', self::DEFAULT_REPO);
        $url = sprintf(self::GITHUB_API, $repo);

        $status = $this->loadStatus();
        $etag = $status['etag'] ?? '';

        $headers = [
            'Accept: application/vnd.github+json',
            'User-Agent: ' . self::USER_AGENT,
            'X-GitHub-Api-Version: 2022-11-28',
        ];

        if ($etag !== '') {
            $headers[] = 'If-None-Match: ' . $etag;
        }

        $ch = curl_init();
        if ($ch === false) {
            $this->saveCheckResult($result, $status);
            return $result;
        }

        $responseHeaders = [];
        $curlOpts = [
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_HEADERFUNCTION => static function ($ch, string $header) use (&$responseHeaders): int {
                $parts = explode(':', $header, 2);
                if (count($parts) === 2) {
                    $responseHeaders[strtolower(trim($parts[0]))] = trim($parts[1]);
                }
                return strlen($header);
            },
        ];

        $caBundle = (string) $this->config->get('ca_bundle', '');
        if ($caBundle !== '' && file_exists($caBundle)) {
            $curlOpts[CURLOPT_CAINFO] = $caBundle;
        }

        curl_setopt_array($ch, $curlOpts);

        $response = curl_exec($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        // 304 Not Modified — use cached data
        if ($httpCode === 304) {
            $status['last_check_ts'] = time();
            $status['last_check_time'] = date('Y-m-d H:i:s');
            $this->saveStatus($status);
            $result['available'] = $status['update_available'] ?? false;
            $result['latest_version'] = $status['latest_version'] ?? '';
            $result['download_url'] = $status['latest_download_url'] ?? '';
            $result['release_notes'] = $status['latest_release_notes'] ?? '';
            $result['published_at'] = $status['latest_published_at'] ?? '';
            return $result;
        }

        if ($httpCode !== 200 || !is_string($response)) {
            $this->saveCheckResult($result, $status);
            return $result;
        }

        $data = @json_decode($response, true);
        if (!is_array($data)) {
            $this->saveCheckResult($result, $status);
            return $result;
        }

        $tagName = (string) ($data['tag_name'] ?? '');
        $latestVersion = ltrim($tagName, 'vV');
        $currentVersion = $this->getCurrentVersion();
        $downloadUrl = (string) ($data['zipball_url'] ?? '');
        $releaseNotes = (string) ($data['body'] ?? '');
        $publishedAt = (string) ($data['published_at'] ?? '');

        // Validate download URL — must be HTTPS and from GitHub
        if ($downloadUrl !== '' && !$this->isValidDownloadUrl($downloadUrl)) {
            $downloadUrl = '';
        }

        $available = $latestVersion !== '' && $currentVersion !== ''
            && version_compare($latestVersion, $currentVersion, '>');

        $result = [
            'available' => $available,
            'latest_version' => $latestVersion,
            'download_url' => $downloadUrl,
            'release_notes' => $releaseNotes,
            'published_at' => $publishedAt,
        ];

        // Update status with new etag
        $newEtag = $responseHeaders['etag'] ?? '';
        $status['etag'] = $newEtag;

        $this->saveCheckResult($result, $status);

        return $result;
    }

    /**
     * Get the current application version from the VERSION file.
     */
    public function getCurrentVersion(): string
    {
        $versionFile = dirname(__DIR__, 2) . '/VERSION';
        if (!file_exists($versionFile)) {
            return 'unknown';
        }

        return trim((string) file_get_contents($versionFile));
    }

    /**
     * If auto_update is enabled and an update is available, trigger it.
     *
     * Checks both the status file toggle (admin panel) and the config file setting.
     * The status file toggle takes precedence as it reflects the user's latest choice.
     */
    public function maybeAutoUpdate(): void
    {
        $status = $this->loadStatus();

        // Status file toggle (set via admin panel) takes precedence over config
        $autoUpdate = $status['auto_update_enabled'] ?? (bool) $this->config->get('auto_update', true);
        if (!$autoUpdate) {
            return;
        }

        if (!($status['update_available'] ?? false)) {
            return;
        }

        $downloadUrl = $status['latest_download_url'] ?? '';
        $targetVersion = $status['latest_version'] ?? '';

        if ($downloadUrl === '' || $targetVersion === '') {
            return;
        }

        // Don't auto-update if an update is already in progress
        if ($this->isUpdateInProgress($status)) {
            return;
        }

        try {
            $manager = new UpdateManager($this->config);
            $manager->update($targetVersion, $downloadUrl);
        } catch (\Throwable $e) {
            // Log but don't crash
            $this->logError('Auto-update failed: ' . $e->getMessage());
        }
    }

    /**
     * Get the path to the update status JSON file.
     */
    public function getStatusFilePath(): ?string
    {
        $dbPath = (string) $this->config->get('db_path', '');
        $dataDir = $dbPath !== '' ? dirname($dbPath) : dirname(__DIR__, 2) . '/data';

        if (!is_dir($dataDir)) {
            return null;
        }

        return $dataDir . '/update_status.json';
    }

    /**
     * Load the update status from the JSON file.
     *
     * @return array<string, mixed>
     */
    public function loadStatus(): array
    {
        $file = $this->getStatusFilePath();
        if ($file === null || !file_exists($file)) {
            return $this->getDefaultStatus();
        }

        $data = @json_decode((string) file_get_contents($file), true);
        if (!is_array($data)) {
            return $this->getDefaultStatus();
        }

        return $data;
    }

    /**
     * Save the update status to the JSON file.
     *
     * @param array<string, mixed> $data
     */
    public function saveStatus(array $data): void
    {
        $file = $this->getStatusFilePath();
        if ($file === null) {
            return;
        }

        @file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
    }

    /**
     * Validate that a download URL is safe (HTTPS, GitHub domain).
     */
    private function isValidDownloadUrl(string $url): bool
    {
        if (!str_starts_with($url, 'https://')) {
            return false;
        }

        $host = parse_url($url, PHP_URL_HOST);
        if (!is_string($host)) {
            return false;
        }

        $allowedHosts = ['github.com', 'api.github.com', 'codeload.github.com'];
        return in_array($host, $allowedHosts, true);
    }

    /**
     * Check if an update is currently in progress (with stale timeout).
     *
     * @param array<string, mixed> $status
     */
    private function isUpdateInProgress(array $status): bool
    {
        if (!($status['update_in_progress'] ?? false)) {
            return false;
        }

        $since = (int) ($status['update_in_progress_since'] ?? 0);
        if ($since > 0 && (time() - $since) > self::STALE_LOCK_TIMEOUT) {
            return false; // Lock is stale
        }

        return true;
    }

    /**
     * Save check results into the status file.
     *
     * @param array{available: bool, latest_version: string, download_url: string, release_notes: string, published_at: string} $result
     * @param array<string, mixed> $status
     */
    private function saveCheckResult(array $result, array $status): void
    {
        $status['current_version'] = $this->getCurrentVersion();
        $status['last_check_ts'] = time();
        $status['last_check_time'] = date('Y-m-d H:i:s');
        $status['latest_version'] = $result['latest_version'];
        $status['latest_download_url'] = $result['download_url'];
        $status['latest_release_notes'] = $result['release_notes'];
        $status['latest_published_at'] = $result['published_at'];
        $status['update_available'] = $result['available'];

        // Preserve admin panel toggle; only set default if not yet defined
        if (!isset($status['auto_update_enabled'])) {
            $status['auto_update_enabled'] = (bool) $this->config->get('auto_update', true);
        }

        $this->saveStatus($status);
    }

    /**
     * Get the default status structure.
     *
     * @return array<string, mixed>
     */
    private function getDefaultStatus(): array
    {
        return [
            'current_version' => $this->getCurrentVersion(),
            'last_check_ts' => 0,
            'last_check_time' => null,
            'latest_version' => '',
            'latest_download_url' => '',
            'latest_release_notes' => '',
            'latest_published_at' => '',
            'update_available' => false,
            'auto_update_enabled' => (bool) $this->config->get('auto_update', true),
            'update_in_progress' => false,
            'update_in_progress_since' => null,
            'etag' => '',
            'last_update' => null,
            'history' => [],
            'errors' => [],
        ];
    }

    /**
     * Log an update error to the status file.
     */
    private function logError(string $message): void
    {
        $status = $this->loadStatus();
        if (!isset($status['errors']) || !is_array($status['errors'])) {
            $status['errors'] = [];
        }

        array_unshift($status['errors'], [
            'time' => date('Y-m-d H:i:s'),
            'message' => $message,
        ]);

        // Keep only last 20 errors
        $status['errors'] = array_slice($status['errors'], 0, 20);
        $this->saveStatus($status);
    }
}
