<?php

declare(strict_types=1);

/**
 * reportedip-honeypot-server - Entry Point
 *
 * All requests are routed through this single file.
 */

// Error handling for production
set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
    if (!(error_reporting() & $severity)) {
        return false;
    }
    throw new \ErrorException($message, 0, $severity, $file, $line);
});

// Autoloader
$autoloader = __DIR__ . '/../vendor/autoload.php';
if (file_exists($autoloader)) {
    require $autoloader;
} else {
    // Fallback: simple PSR-4 autoloader if Composer is not available
    spl_autoload_register(static function (string $class): void {
        $prefix = 'ReportedIp\\Honeypot\\';
        if (!str_starts_with($class, $prefix)) {
            return;
        }

        $file = __DIR__ . '/../src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (file_exists($file)) {
            require $file;
        }
    });
}

use ReportedIp\Honeypot\Core\{App, Config};

// Load configuration
$configPath = __DIR__ . '/../config/config.php';
if (!file_exists($configPath)) {
    // Launch Web Installer
    (new \ReportedIp\Honeypot\Installer\WebInstaller(__DIR__ . '/..'))->run();
    exit;
}

$app = new App(Config::fromFile($configPath));
$app->handle();
