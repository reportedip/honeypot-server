<?php

declare(strict_types=1);

/**
 * reportedip-honeypot-server CLI Tool
 *
 * Usage:
 *   php cli.php <command> [options]
 *
 * Commands:
 *   stats                          Show attack statistics
 *   process-queue                  Send pending reports to API
 *   cleanup [--days=90]            Remove old log entries
 *   whitelist-add <ip> [desc]      Add IP to whitelist
 *   whitelist-remove <ip>          Remove IP from whitelist
 *   whitelist-list                 Show all whitelist entries
 *   test-api                       Test API connectivity
 */

if (PHP_SAPI !== 'cli') {
    echo 'This script must be run from the command line.';
    exit(1);
}

$baseDir = __DIR__;

// Autoloader
$autoloader = $baseDir . '/vendor/autoload.php';
if (file_exists($autoloader)) {
    require $autoloader;
} else {
    spl_autoload_register(static function (string $class) use ($baseDir): void {
        $prefix = 'ReportedIp\\Honeypot\\';
        $len = strlen($prefix);
        if (strncmp($prefix, $class, $len) !== 0) {
            return;
        }
        $relativeClass = substr($class, $len);
        $file = $baseDir . '/src/' . str_replace('\\', '/', $relativeClass) . '.php';
        if (file_exists($file)) {
            require $file;
        }
    });
}

use ReportedIp\Honeypot\Api\ReportClient;
use ReportedIp\Honeypot\Api\ReportQueue;
use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Persistence\Logger;
use ReportedIp\Honeypot\Persistence\VisitorLogger;
use ReportedIp\Honeypot\Persistence\Whitelist;
use ReportedIp\Honeypot\Update\UpdateChecker;
use ReportedIp\Honeypot\Update\UpdateManager;

// Load configuration
$configPath = $baseDir . '/config/config.php';
if (!file_exists($configPath)) {
    fwrite(STDERR, "Error: Configuration not found. Open the website in your browser to run the web installer.\n");
    exit(1);
}

$config = Config::fromFile($configPath);
$db = new Database($config->get('db_path', $baseDir . '/data/honeypot.sqlite'));
$db->initialize();

// Parse command
$command = $argv[1] ?? 'help';

switch ($command) {
    case 'stats':
        commandStats($db, $config);
        break;

    case 'process-queue':
        commandProcessQueue($db, $config);
        break;

    case 'cleanup':
        $days = getOption($argv, '--days', '90');
        commandCleanup($db, $config, (int) $days);
        break;

    case 'whitelist-add':
        $ip = $argv[2] ?? null;
        $description = $argv[3] ?? '';
        if ($ip === null) {
            fwrite(STDERR, "Usage: php cli.php whitelist-add <ip> [description]\n");
            exit(1);
        }
        commandWhitelistAdd($db, $ip, $description);
        break;

    case 'whitelist-remove':
        $ip = $argv[2] ?? null;
        if ($ip === null) {
            fwrite(STDERR, "Usage: php cli.php whitelist-remove <ip>\n");
            exit(1);
        }
        commandWhitelistRemove($db, $ip);
        break;

    case 'whitelist-list':
        commandWhitelistList($db);
        break;

    case 'test-api':
        commandTestApi($config);
        break;

    case 'check-update':
        commandCheckUpdate($config);
        break;

    case 'update':
        $rollback = in_array('--rollback', $argv, true);
        commandUpdate($config, $rollback);
        break;

    case 'help':
    case '--help':
    case '-h':
    default:
        showHelp();
        break;
}

exit(0);

// ---- Command Implementations ----

function commandStats(Database $db, Config $config): void
{
    $logger = new Logger($db, $config);
    $stats = $logger->getStats();

    echo "\n";
    echo "=== Honeypot Statistics ===\n\n";
    echo sprintf("  Total events:    %d\n", $stats['total']);
    echo sprintf("  Today:           %d\n", $stats['today']);
    echo sprintf("  Unique IPs:      %d\n", $stats['unique_ips']);
    echo sprintf("  Pending reports: %d\n", $stats['pending']);

    if (!empty($stats['top_ips'])) {
        echo "\n  Top 10 IPs:\n";
        foreach ($stats['top_ips'] as $row) {
            echo sprintf("    %-18s %d events\n", $row['ip'], $row['cnt']);
        }
    }

    if (!empty($stats['top_categories'])) {
        echo "\n  Top 10 Categories:\n";
        foreach ($stats['top_categories'] as $row) {
            echo sprintf("    %-20s %d events\n", $row['categories'], $row['cnt']);
        }
    }

    echo "\n";
}

function commandProcessQueue(Database $db, Config $config): void
{
    $client = new ReportClient($config);
    $queue = new ReportQueue($db, $client, $config);

    $queueSize = $queue->getQueueSize();
    echo sprintf("Queue size: %d pending reports\n", $queueSize);

    if ($queueSize === 0) {
        echo "Nothing to process.\n";
        return;
    }

    $result = $queue->process();
    echo sprintf(
        "Processed: %d sent, %d failed, %d skipped\n",
        $result['sent'],
        $result['failed'],
        $result['skipped']
    );

    if (!empty($result['errors'])) {
        echo "\nErrors:\n";
        foreach ($result['errors'] as $error) {
            echo sprintf("  - %s\n", $error);
        }
        echo sprintf("\nSee data/api_errors.log for full details.\n");
    }

    $remaining = $queue->getQueueSize();
    if ($remaining > 0) {
        echo sprintf("Remaining: %d reports still pending\n", $remaining);
    }

    // Auto-cleanup old entries
    $retentionDays = (int) $config->get('log_retention_days', 90);
    $logger = new Logger($db, $config);
    $cleaned = $logger->cleanup($retentionDays);
    if ($cleaned > 0) {
        echo sprintf("Cleanup: %d log entries older than %d days removed.\n", $cleaned, $retentionDays);
    }

    // Auto-cleanup old visitor entries
    $visitorLogger = new VisitorLogger($db);
    $visitorsCleaned = $visitorLogger->cleanup($retentionDays);
    if ($visitorsCleaned > 0) {
        echo sprintf("Cleanup: %d visitor entries older than %d days removed.\n", $visitorsCleaned, $retentionDays);
    }

    // Save cron run status for the admin dashboard
    saveCronStatus($config, $result, $remaining, $cleaned);
}

function commandCleanup(Database $db, Config $config, int $days): void
{
    $logger = new Logger($db, $config);
    $deleted = $logger->cleanup($days);
    echo sprintf("Cleaned up: %d entries older than %d days removed.\n", $deleted, $days);
}

function commandWhitelistAdd(Database $db, string $ip, string $description): void
{
    if (filter_var($ip, FILTER_VALIDATE_IP) === false && strpos($ip, '/') === false) {
        fwrite(STDERR, "Error: Invalid IP address or CIDR range: {$ip}\n");
        exit(1);
    }

    $whitelist = new Whitelist($db);
    $whitelist->add($ip, $description);
    echo "Added to whitelist: {$ip}\n";
}

function commandWhitelistRemove(Database $db, string $ip): void
{
    $whitelist = new Whitelist($db);
    $whitelist->remove($ip);
    echo "Removed from whitelist: {$ip}\n";
}

function commandWhitelistList(Database $db): void
{
    $whitelist = new Whitelist($db);
    $entries = $whitelist->getAll();

    if (empty($entries)) {
        echo "Whitelist is empty.\n";
        return;
    }

    echo "\n=== Whitelist ===\n\n";
    echo sprintf("  %-18s %-8s %-20s %s\n", 'IP Address', 'Active', 'Added', 'Description');
    echo "  " . str_repeat('-', 70) . "\n";

    foreach ($entries as $entry) {
        echo sprintf(
            "  %-18s %-8s %-20s %s\n",
            $entry['ip_address'],
            $entry['is_active'] ? 'Yes' : 'No',
            $entry['added_date'],
            $entry['description'] ?? ''
        );
    }

    echo "\n";
}

function commandTestApi(Config $config): void
{
    $apiKey = $config->get('api_key', '');
    $apiUrl = $config->get('api_url', '');

    echo "Testing API connectivity...\n";
    echo sprintf("  URL: %s\n", $apiUrl);
    echo sprintf("  Key: %s...%s\n",
        substr($apiKey, 0, 8),
        strlen($apiKey) > 8 ? substr($apiKey, -4) : ''
    );

    if (empty($apiKey)) {
        echo "  Error: No API key configured.\n";
        exit(1);
    }

    if (!extension_loaded('curl')) {
        echo "  Error: cURL extension not loaded.\n";
        exit(1);
    }

    // Test connectivity with a HEAD-like request
    $ch = curl_init();
    $curlOpts = [
        CURLOPT_URL            => $apiUrl,
        CURLOPT_NOBODY         => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_HTTPHEADER     => [
            'X-Key: ' . $apiKey,
            'User-Agent: reportedip-honeypot-server/1.0.0',
        ],
    ];

    $caBundle = $config->get('ca_bundle', '');
    if ($caBundle !== '' && file_exists($caBundle)) {
        $curlOpts[CURLOPT_CAINFO] = $caBundle;
    }

    curl_setopt_array($ch, $curlOpts);

    curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    if (!empty($error)) {
        echo sprintf("  Connection failed: %s\n", $error);
        exit(1);
    }

    echo sprintf("  HTTP Status: %d\n", $httpCode);

    if ($httpCode >= 200 && $httpCode < 500) {
        echo "  API endpoint is reachable.\n";
    } else {
        echo "  Warning: Unexpected response code.\n";
    }
}

/**
 * Extract a --option=value from argv.
 */
function getOption(array $argv, string $option, string $default): string
{
    foreach ($argv as $arg) {
        if (strpos($arg, $option . '=') === 0) {
            return substr($arg, strlen($option) + 1);
        }
    }
    return $default;
}

/**
 * Save cron run status to a JSON file for the admin dashboard.
 *
 * @param array{sent: int, failed: int, skipped: int, errors: string[]} $result
 */
function saveCronStatus(Config $config, array $result, int $remaining, int $cleaned = 0): void
{
    $dbPath = $config->get('db_path', '');
    $dataDir = $dbPath !== '' ? dirname($dbPath) : __DIR__ . '/data';

    if (!is_dir($dataDir)) {
        return;
    }

    $statusFile = $dataDir . '/cron_status.json';

    // Load existing history
    $existing = [];
    if (file_exists($statusFile)) {
        $existing = @json_decode((string) file_get_contents($statusFile), true) ?: [];
    }

    // Update current status
    $existing['last_run'] = date('Y-m-d H:i:s');
    $existing['queue_mode'] = 'cron';
    $existing['last_result'] = [
        'sent'      => $result['sent'],
        'failed'    => $result['failed'],
        'skipped'   => $result['skipped'],
        'remaining' => $remaining,
        'cleaned'   => $cleaned,
        'had_errors' => !empty($result['errors']),
    ];

    // Keep last 24 runs
    if (!isset($existing['history'])) {
        $existing['history'] = [];
    }
    array_unshift($existing['history'], [
        'time'   => date('Y-m-d H:i:s'),
        'sent'   => $result['sent'],
        'failed' => $result['failed'],
    ]);
    $existing['history'] = array_slice($existing['history'], 0, 24);

    // Count totals
    $existing['total_sent'] = ($existing['total_sent'] ?? 0) + $result['sent'];
    $existing['total_failed'] = ($existing['total_failed'] ?? 0) + $result['failed'];
    $existing['runs_count'] = ($existing['runs_count'] ?? 0) + 1;

    @file_put_contents($statusFile, json_encode($existing, JSON_PRETTY_PRINT), LOCK_EX);
}

function commandCheckUpdate(Config $config): void
{
    $checker = new UpdateChecker($config);
    $currentVersion = $checker->getCurrentVersion();

    echo "\n";
    echo "=== Update Check ===\n\n";
    echo sprintf("  Current version: %s\n", $currentVersion);
    echo "  Checking GitHub for updates...\n";

    try {
        $result = $checker->forceCheck();
    } catch (\Throwable $e) {
        echo sprintf("  Error: %s\n\n", $e->getMessage());
        exit(1);
    }

    if ($result['available']) {
        echo sprintf("  Latest version:  %s (update available!)\n", $result['latest_version']);
        echo sprintf("  Published:       %s\n", $result['published_at'] !== '' ? substr($result['published_at'], 0, 10) : 'unknown');
        if ($result['release_notes'] !== '') {
            echo "\n  Release Notes:\n";
            foreach (explode("\n", $result['release_notes']) as $line) {
                echo "    " . $line . "\n";
            }
        }
        echo "\n  Run 'php cli.php update' to apply the update.\n";
    } else {
        echo "  You are running the latest version.\n";
    }
    echo "\n";
}

function commandUpdate(Config $config, bool $rollback): void
{
    $manager = new UpdateManager($config);

    if ($rollback) {
        $backups = $manager->getBackups();
        if (empty($backups)) {
            echo "No backups available for rollback.\n";
            exit(1);
        }

        $latest = $backups[0];
        echo sprintf("Rolling back to backup: %s (version %s)\n", $latest['name'], $latest['version']);

        $result = $manager->rollback($latest['path']);
        echo $result['message'] . "\n";
        exit($result['success'] ? 0 : 1);
    }

    $checker = new UpdateChecker($config);
    $status = $checker->loadStatus();

    // If no recent check, force one
    if (empty($status['latest_version'])) {
        echo "Checking for updates...\n";
        $checkResult = $checker->forceCheck();
        if (!$checkResult['available']) {
            echo "Already running the latest version.\n";
            exit(0);
        }
        $status = $checker->loadStatus();
    }

    if (!($status['update_available'] ?? false)) {
        echo "No update available. Run 'php cli.php check-update' first.\n";
        exit(0);
    }

    $downloadUrl = $status['latest_download_url'] ?? '';
    $targetVersion = $status['latest_version'] ?? '';

    if ($downloadUrl === '' || $targetVersion === '') {
        echo "Error: Missing download URL or target version.\n";
        exit(1);
    }

    echo "\n=== Self-Update ===\n\n";
    echo sprintf("  From: %s\n", $checker->getCurrentVersion());
    echo sprintf("  To:   %s\n\n", $targetVersion);

    // Preflight
    echo "  Running preflight checks...\n";
    $preflight = $manager->preflightCheck();
    if (!empty($preflight['errors'])) {
        echo "  Preflight FAILED:\n";
        foreach ($preflight['errors'] as $error) {
            echo "    - " . $error . "\n";
        }
        exit(1);
    }
    echo "  Preflight OK.\n";

    echo "  Downloading update...\n";
    $result = $manager->update($targetVersion, $downloadUrl);

    if ($result['success']) {
        echo "  " . $result['message'] . "\n";
        if ($result['backup_path'] !== '') {
            echo sprintf("  Backup saved to: %s\n", $result['backup_path']);
        }
    } else {
        echo "  Update FAILED: " . $result['message'] . "\n";
        if (!empty($result['errors'])) {
            foreach ($result['errors'] as $error) {
                echo "    - " . $error . "\n";
            }
        }
        exit(1);
    }

    echo "\n";
}

function showHelp(): void
{
    echo "\n";
    echo "reportedip-honeypot-server CLI\n\n";
    echo "Usage: php cli.php <command> [options]\n\n";
    echo "Commands:\n";
    echo "  stats                          Show attack statistics\n";
    echo "  process-queue                  Send pending reports to API\n";
    echo "  cleanup [--days=90]            Remove old log entries\n";
    echo "  whitelist-add <ip> [desc]      Add IP to whitelist\n";
    echo "  whitelist-remove <ip>          Remove IP from whitelist\n";
    echo "  whitelist-list                 Show all whitelist entries\n";
    echo "  test-api                       Test API connectivity\n";
    echo "  check-update                   Check for new versions\n";
    echo "  update                         Apply available update\n";
    echo "  update --rollback              Restore most recent backup\n";
    echo "  help                           Show this help message\n";
    echo "\n";
}
