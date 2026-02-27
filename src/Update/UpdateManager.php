<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Update;

use ReportedIp\Honeypot\Core\Config;

/**
 * Orchestrates the complete self-update process.
 *
 * Download → Backup → Replace → Verify with automatic rollback on failure.
 */
final class UpdateManager
{
    private const MAX_BACKUPS = 3;
    private const STALE_LOCK_TIMEOUT = 600; // 10 minutes

    /**
     * Paths that must never be overwritten during an update.
     */
    private const PROTECTED_PATHS = [
        'config/config.php',
        'data',
        'vendor',
    ];

    /**
     * Files that must exist in the extracted release for sanity validation.
     */
    private const REQUIRED_FILES = [
        'src/Core/App.php',
        'VERSION',
        'public/index.php',
    ];

    /**
     * Directories and files to include in the backup.
     */
    private const BACKUP_ITEMS = [
        'src',
        'templates',
        'public/index.php',
        'cli.php',
        'install.php',
        'VERSION',
        'composer.json',
        'tests',
    ];

    private Config $config;
    private string $projectRoot;

    public function __construct(Config $config)
    {
        $this->config = $config;
        $this->projectRoot = dirname(__DIR__, 2);
    }

    /**
     * Execute the full update process.
     *
     * @return array{success: bool, from_version: string, to_version: string, message: string, backup_path: string, errors: string[]}
     */
    public function update(string $targetVersion, string $downloadUrl): array
    {
        $checker = new UpdateChecker($this->config);
        $fromVersion = $checker->getCurrentVersion();
        $errors = [];

        $result = [
            'success' => false,
            'from_version' => $fromVersion,
            'to_version' => $targetVersion,
            'message' => '',
            'backup_path' => '',
            'errors' => [],
        ];

        // 1. Preflight check
        $preflight = $this->preflightCheck();
        if (!empty($preflight['errors'])) {
            $result['message'] = 'Preflight check failed';
            $result['errors'] = $preflight['errors'];
            $this->recordHistory($result);
            return $result;
        }

        // Validate download URL
        if (!str_starts_with($downloadUrl, 'https://')) {
            $result['message'] = 'Invalid download URL: must use HTTPS';
            $result['errors'] = ['Download URL must use HTTPS'];
            $this->recordHistory($result);
            return $result;
        }

        $host = parse_url($downloadUrl, PHP_URL_HOST);
        if (!is_string($host) || !in_array($host, ['github.com', 'api.github.com', 'codeload.github.com'], true)) {
            $result['message'] = 'Invalid download URL: must be from GitHub';
            $result['errors'] = ['Download URL must be from GitHub'];
            $this->recordHistory($result);
            return $result;
        }

        // 2. Set lock
        $this->setLock(true);

        try {
            // 3. Download
            $tmpDir = $this->getTmpDir();
            $zipPath = $tmpDir . '/update-' . $targetVersion . '.zip';
            $downloadResult = $this->download($downloadUrl, $zipPath);
            if (!$downloadResult['success']) {
                $result['message'] = 'Download failed: ' . $downloadResult['error'];
                $result['errors'][] = $downloadResult['error'];
                $this->recordHistory($result);
                return $result;
            }

            // 4. Extract
            $extractDir = $tmpDir . '/update-' . $targetVersion;
            $extractResult = $this->extract($zipPath, $extractDir);
            if (!$extractResult['success']) {
                $result['message'] = 'Extraction failed: ' . $extractResult['error'];
                $result['errors'][] = $extractResult['error'];
                $this->cleanup($zipPath, $extractDir);
                $this->recordHistory($result);
                return $result;
            }

            // 5. Find the actual source root (GitHub wraps in a subdirectory)
            $sourceRoot = $this->findSourceRoot($extractDir);
            if ($sourceRoot === null) {
                $result['message'] = 'Could not find source root in extracted archive';
                $result['errors'][] = 'Invalid archive structure';
                $this->cleanup($zipPath, $extractDir);
                $this->recordHistory($result);
                return $result;
            }

            // 6. Sanity check
            foreach (self::REQUIRED_FILES as $requiredFile) {
                if (!file_exists($sourceRoot . '/' . $requiredFile)) {
                    $result['message'] = 'Sanity check failed: missing ' . $requiredFile;
                    $result['errors'][] = 'Missing required file: ' . $requiredFile;
                    $this->cleanup($zipPath, $extractDir);
                    $this->recordHistory($result);
                    return $result;
                }
            }

            // 7. Backup
            $backupPath = $this->createBackup($fromVersion);
            if ($backupPath === '') {
                $result['message'] = 'Backup creation failed';
                $result['errors'][] = 'Could not create backup';
                $this->cleanup($zipPath, $extractDir);
                $this->recordHistory($result);
                return $result;
            }
            $result['backup_path'] = $backupPath;

            // 8. Replace files
            $replaceResult = $this->replaceFiles($sourceRoot);
            if (!$replaceResult['success']) {
                $result['message'] = 'File replacement failed, rolling back';
                $result['errors'] = $replaceResult['errors'];
                $this->rollback($backupPath);
                $this->cleanup($zipPath, $extractDir);
                $this->recordHistory($result);
                return $result;
            }

            // 9. Verify
            $newVersion = trim((string) @file_get_contents($this->projectRoot . '/VERSION'));
            if ($newVersion !== $targetVersion) {
                $result['message'] = sprintf('Verification failed: expected %s, got %s. Rolling back.', $targetVersion, $newVersion);
                $result['errors'][] = 'Version mismatch after update';
                $this->rollback($backupPath);
                $this->cleanup($zipPath, $extractDir);
                $this->recordHistory($result);
                return $result;
            }

            // 10. Cleanup
            $this->cleanup($zipPath, $extractDir);
            $this->pruneBackups();

            $result['success'] = true;
            $result['message'] = sprintf('Updated successfully from %s to %s', $fromVersion, $targetVersion);
            $this->recordHistory($result);

            return $result;
        } finally {
            $this->setLock(false);
        }
    }

    /**
     * Check system requirements for update.
     *
     * @return array{ok: bool, checks: array<string, array{ok: bool, message: string}>, errors: string[]}
     */
    public function preflightCheck(): array
    {
        $checks = [];
        $errors = [];

        // ext-zip
        $zipLoaded = extension_loaded('zip');
        $checks['zip_extension'] = [
            'ok' => $zipLoaded,
            'message' => $zipLoaded ? 'ZipArchive available' : 'ext-zip is required for updates',
        ];
        if (!$zipLoaded) {
            $errors[] = 'PHP zip extension is not loaded';
        }

        // ext-curl
        $curlLoaded = extension_loaded('curl');
        $checks['curl_extension'] = [
            'ok' => $curlLoaded,
            'message' => $curlLoaded ? 'cURL available' : 'ext-curl is required for updates',
        ];
        if (!$curlLoaded) {
            $errors[] = 'PHP curl extension is not loaded';
        }

        // src/ writable
        $srcWritable = is_writable($this->projectRoot . '/src');
        $checks['src_writable'] = [
            'ok' => $srcWritable,
            'message' => $srcWritable ? 'src/ is writable' : 'src/ is not writable',
        ];
        if (!$srcWritable) {
            $errors[] = 'src/ directory is not writable';
        }

        // data/tmp/ writable
        $tmpDir = $this->getTmpDir();
        if (!is_dir($tmpDir)) {
            @mkdir($tmpDir, 0775, true);
        }
        $tmpWritable = is_dir($tmpDir) && is_writable($tmpDir);
        $checks['tmp_writable'] = [
            'ok' => $tmpWritable,
            'message' => $tmpWritable ? 'data/tmp/ is writable' : 'data/tmp/ is not writable',
        ];
        if (!$tmpWritable) {
            $errors[] = 'data/tmp/ directory is not writable';
        }

        // data/backups/ available
        $backupDir = $this->getBackupDir();
        if (!is_dir($backupDir)) {
            @mkdir($backupDir, 0775, true);
        }
        $backupWritable = is_dir($backupDir) && is_writable($backupDir);
        $checks['backup_writable'] = [
            'ok' => $backupWritable,
            'message' => $backupWritable ? 'data/backups/ is writable' : 'data/backups/ is not writable',
        ];
        if (!$backupWritable) {
            $errors[] = 'data/backups/ directory is not writable';
        }

        return [
            'ok' => empty($errors),
            'checks' => $checks,
            'errors' => $errors,
        ];
    }

    /**
     * Restore a backup by copying files back to the project root.
     *
     * @return array{success: bool, message: string}
     */
    public function rollback(string $backupPath): array
    {
        if (!is_dir($backupPath)) {
            return ['success' => false, 'message' => 'Backup directory not found: ' . $backupPath];
        }

        try {
            $this->copyDirectory($backupPath, $this->projectRoot);
            return ['success' => true, 'message' => 'Rollback completed from ' . basename($backupPath)];
        } catch (\Throwable $e) {
            return ['success' => false, 'message' => 'Rollback failed: ' . $e->getMessage()];
        }
    }

    /**
     * Get a list of available backups.
     *
     * @return array<int, array{path: string, name: string, version: string, timestamp: string, size: string}>
     */
    public function getBackups(): array
    {
        $backupDir = $this->getBackupDir();
        if (!is_dir($backupDir)) {
            return [];
        }

        $backups = [];
        $entries = @scandir($backupDir);
        if (!is_array($entries)) {
            return [];
        }

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            $path = $backupDir . '/' . $entry;
            if (!is_dir($path)) {
                continue;
            }

            // Parse backup directory name: backup-{version}-{timestamp}
            if (preg_match('/^backup-(.+?)-(\d+)$/', $entry, $matches)) {
                $backups[] = [
                    'path' => $path,
                    'name' => $entry,
                    'version' => $matches[1],
                    'timestamp' => date('Y-m-d H:i:s', (int) $matches[2]),
                    'size' => $this->getDirectorySize($path),
                ];
            }
        }

        // Sort newest first
        usort($backups, static function (array $a, array $b): int {
            return strcmp($b['name'], $a['name']);
        });

        return $backups;
    }

    /**
     * Download a file from a URL.
     *
     * @return array{success: bool, error: string}
     */
    private function download(string $url, string $destination): array
    {
        $fp = @fopen($destination, 'w');
        if ($fp === false) {
            return ['success' => false, 'error' => 'Cannot create temporary file'];
        }

        $ch = curl_init();
        if ($ch === false) {
            fclose($fp);
            @unlink($destination);
            return ['success' => false, 'error' => 'cURL init failed'];
        }

        $curlOpts = [
            CURLOPT_URL            => $url,
            CURLOPT_FILE           => $fp,
            CURLOPT_TIMEOUT        => 120,
            CURLOPT_CONNECTTIMEOUT => 15,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_HTTPHEADER     => [
                'Accept: application/vnd.github+json',
                'User-Agent: ' . UpdateChecker::class,
            ],
        ];

        $caBundle = (string) $this->config->get('ca_bundle', '');
        if ($caBundle !== '' && file_exists($caBundle)) {
            $curlOpts[CURLOPT_CAINFO] = $caBundle;
        }

        curl_setopt_array($ch, $curlOpts);

        curl_exec($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);
        fclose($fp);

        if ($curlError !== '') {
            @unlink($destination);
            return ['success' => false, 'error' => 'cURL error: ' . $curlError];
        }

        if ($httpCode < 200 || $httpCode >= 300) {
            @unlink($destination);
            return ['success' => false, 'error' => sprintf('HTTP %d from download URL', $httpCode)];
        }

        return ['success' => true, 'error' => ''];
    }

    /**
     * Extract a ZIP archive.
     *
     * @return array{success: bool, error: string}
     */
    private function extract(string $zipPath, string $destination): array
    {
        if (!extension_loaded('zip')) {
            return ['success' => false, 'error' => 'ext-zip is not loaded'];
        }

        $zip = new \ZipArchive();
        $openResult = $zip->open($zipPath);
        if ($openResult !== true) {
            return ['success' => false, 'error' => 'Failed to open ZIP archive (code: ' . $openResult . ')'];
        }

        if (!is_dir($destination)) {
            @mkdir($destination, 0775, true);
        }

        $zip->extractTo($destination);
        $zip->close();

        return ['success' => true, 'error' => ''];
    }

    /**
     * Find the actual source root in the extracted archive.
     *
     * GitHub ZIPs contain a wrapper directory like {repo}-{hash}/.
     */
    private function findSourceRoot(string $extractDir): ?string
    {
        // Check if the required files are directly in the extract dir
        if (file_exists($extractDir . '/VERSION')) {
            return $extractDir;
        }

        // Look one level deep
        $entries = @scandir($extractDir);
        if (!is_array($entries)) {
            return null;
        }

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            $subDir = $extractDir . '/' . $entry;
            if (is_dir($subDir) && file_exists($subDir . '/VERSION')) {
                return $subDir;
            }
        }

        return null;
    }

    /**
     * Create a backup of current files.
     */
    private function createBackup(string $version): string
    {
        $backupDir = $this->getBackupDir();
        if (!is_dir($backupDir)) {
            @mkdir($backupDir, 0775, true);
        }

        $backupName = sprintf('backup-%s-%d', $version, time());
        $backupPath = $backupDir . '/' . $backupName;

        if (!@mkdir($backupPath, 0775, true)) {
            return '';
        }

        foreach (self::BACKUP_ITEMS as $item) {
            $source = $this->projectRoot . '/' . $item;
            if (!file_exists($source)) {
                continue;
            }

            $dest = $backupPath . '/' . $item;
            if (is_dir($source)) {
                $this->copyDirectory($source, $dest);
            } else {
                $destDir = dirname($dest);
                if (!is_dir($destDir)) {
                    @mkdir($destDir, 0775, true);
                }
                @copy($source, $dest);
            }
        }

        return $backupPath;
    }

    /**
     * Replace project files from the extracted source.
     *
     * @return array{success: bool, errors: string[]}
     */
    private function replaceFiles(string $sourceRoot): array
    {
        $errors = [];

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($sourceRoot, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $item) {
            /** @var \SplFileInfo $item */
            $relativePath = str_replace('\\', '/', substr($item->getPathname(), strlen($sourceRoot) + 1));

            // Skip protected paths
            if ($this->isProtected($relativePath)) {
                continue;
            }

            $targetPath = $this->projectRoot . '/' . $relativePath;

            if ($item->isDir()) {
                if (!is_dir($targetPath)) {
                    if (!@mkdir($targetPath, 0775, true)) {
                        $errors[] = 'Failed to create directory: ' . $relativePath;
                    }
                }
            } else {
                $targetDir = dirname($targetPath);
                if (!is_dir($targetDir)) {
                    @mkdir($targetDir, 0775, true);
                }
                if (!@copy($item->getPathname(), $targetPath)) {
                    $errors[] = 'Failed to copy: ' . $relativePath;
                }
            }
        }

        return ['success' => empty($errors), 'errors' => $errors];
    }

    /**
     * Check if a relative path is protected from being overwritten.
     */
    private function isProtected(string $relativePath): bool
    {
        foreach (self::PROTECTED_PATHS as $protected) {
            if ($relativePath === $protected || str_starts_with($relativePath, $protected . '/')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Clean up temporary files.
     */
    private function cleanup(string $zipPath, string $extractDir): void
    {
        if (file_exists($zipPath)) {
            @unlink($zipPath);
        }

        if (is_dir($extractDir)) {
            $this->removeDirectory($extractDir);
        }
    }

    /**
     * Remove old backups, keeping only MAX_BACKUPS most recent.
     */
    private function pruneBackups(): void
    {
        $backups = $this->getBackups();

        if (count($backups) <= self::MAX_BACKUPS) {
            return;
        }

        $toRemove = array_slice($backups, self::MAX_BACKUPS);
        foreach ($toRemove as $backup) {
            $this->removeDirectory($backup['path']);
        }
    }

    /**
     * Set or clear the update lock in the status file.
     */
    private function setLock(bool $locked): void
    {
        $checker = new UpdateChecker($this->config);
        $status = $checker->loadStatus();
        $status['update_in_progress'] = $locked;
        $status['update_in_progress_since'] = $locked ? time() : null;
        $checker->saveStatus($status);
    }

    /**
     * Record an update attempt in the status history.
     *
     * @param array{success: bool, from_version: string, to_version: string, message: string, backup_path: string, errors: string[]} $result
     */
    private function recordHistory(array $result): void
    {
        $checker = new UpdateChecker($this->config);
        $status = $checker->loadStatus();

        $historyEntry = [
            'time' => date('Y-m-d H:i:s'),
            'from_version' => $result['from_version'],
            'to_version' => $result['to_version'],
            'success' => $result['success'],
            'message' => $result['message'],
        ];

        if ($result['success']) {
            $status['last_update'] = array_merge($historyEntry, [
                'backup_path' => $result['backup_path'],
            ]);
            $status['current_version'] = $result['to_version'];
            $status['update_available'] = false;
        }

        if (!isset($status['history']) || !is_array($status['history'])) {
            $status['history'] = [];
        }
        array_unshift($status['history'], $historyEntry);
        $status['history'] = array_slice($status['history'], 0, 20);

        $checker->saveStatus($status);
    }

    /**
     * Recursively copy a directory.
     */
    private function copyDirectory(string $source, string $destination): void
    {
        if (!is_dir($destination)) {
            @mkdir($destination, 0775, true);
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($source, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $item) {
            /** @var \SplFileInfo $item */
            $relativePath = substr($item->getPathname(), strlen($source) + 1);
            $targetPath = $destination . '/' . $relativePath;

            if ($item->isDir()) {
                if (!is_dir($targetPath)) {
                    @mkdir($targetPath, 0775, true);
                }
            } else {
                $targetDir = dirname($targetPath);
                if (!is_dir($targetDir)) {
                    @mkdir($targetDir, 0775, true);
                }
                @copy($item->getPathname(), $targetPath);
            }
        }
    }

    /**
     * Recursively remove a directory.
     */
    private function removeDirectory(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($iterator as $item) {
            /** @var \SplFileInfo $item */
            if ($item->isDir()) {
                @rmdir($item->getPathname());
            } else {
                @unlink($item->getPathname());
            }
        }

        @rmdir($dir);
    }

    /**
     * Get a human-readable size for a directory.
     */
    private function getDirectorySize(string $dir): string
    {
        $bytes = 0;

        if (!is_dir($dir)) {
            return '0 B';
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $item) {
            /** @var \SplFileInfo $item */
            if ($item->isFile()) {
                $bytes += $item->getSize();
            }
        }

        if ($bytes === 0) {
            return '0 B';
        }

        $units = ['B', 'KB', 'MB', 'GB'];
        $factor = (int) floor(log($bytes, 1024));
        $factor = min($factor, count($units) - 1);

        return sprintf('%.1f %s', $bytes / pow(1024, $factor), $units[$factor]);
    }

    /**
     * Get the temporary directory path.
     */
    private function getTmpDir(): string
    {
        $dbPath = (string) $this->config->get('db_path', '');
        $dataDir = $dbPath !== '' ? dirname($dbPath) : $this->projectRoot . '/data';

        return $dataDir . '/tmp';
    }

    /**
     * Get the backup directory path.
     */
    private function getBackupDir(): string
    {
        $dbPath = (string) $this->config->get('db_path', '');
        $dataDir = $dbPath !== '' ? dirname($dbPath) : $this->projectRoot . '/data';

        return $dataDir . '/backups';
    }
}
