<?php

declare(strict_types=1);

/**
 * CLI test runner for the honeypot project.
 *
 * Usage:
 *   php tests/run-tests.php                    Run all unit + analyzer tests
 *   php tests/run-tests.php --integration      Include integration tests
 *   php tests/run-tests.php --filter Config    Only run tests matching "Config"
 *   php tests/run-tests.php --verbose          Show extra output
 */

$projectRoot = dirname(__DIR__);

// Autoloader: prefer Composer, fall back to manual PSR-4
$composerAutoload = $projectRoot . '/vendor/autoload.php';
if (file_exists($composerAutoload)) {
    require $composerAutoload;
} else {
    // Manual PSR-4 autoloader
    spl_autoload_register(static function (string $class): void {
        $projectRoot = dirname(__DIR__);
        $prefixes = [
            'ReportedIp\\Honeypot\\Tests\\' => $projectRoot . '/tests/',
            'ReportedIp\\Honeypot\\'        => $projectRoot . '/src/',
        ];

        foreach ($prefixes as $prefix => $baseDir) {
            $len = strlen($prefix);
            if (strncmp($class, $prefix, $len) === 0) {
                $relativeClass = substr($class, $len);
                $file = $baseDir . str_replace('\\', '/', $relativeClass) . '.php';
                if (file_exists($file)) {
                    require $file;
                }
                return;
            }
        }
    });
}

// Load the test framework
require_once $projectRoot . '/tests/TestFramework.php';

// Parse CLI arguments
$options = getopt('', ['filter:', 'verbose', 'integration']);
$filter = $options['filter'] ?? null;
$verbose = isset($options['verbose']);
$includeIntegration = isset($options['integration']);

$framework = new ReportedIp\Honeypot\Tests\TestFramework();
$framework->setVerbose($verbose);

// Discover test classes from directories
$testDirs = [
    $projectRoot . '/tests/Unit',
    $projectRoot . '/tests/Analyzers',
];

if ($includeIntegration) {
    $testDirs[] = $projectRoot . '/tests/Integration';
}

$classesLoaded = 0;

foreach ($testDirs as $dir) {
    if (!is_dir($dir)) {
        if ($verbose) {
            echo sprintf("  Skipping missing directory: %s\n", $dir);
        }
        continue;
    }

    $files = glob($dir . '/*Test.php');
    if ($files === false) {
        continue;
    }

    foreach ($files as $file) {
        $basename = basename($file, '.php');

        // Apply filter
        if ($filter !== null && stripos($basename, $filter) === false) {
            continue;
        }

        require_once $file;

        // Determine namespace from directory
        $relDir = basename(dirname($file));
        switch ($relDir) {
            case 'Unit':
                $namespace = 'ReportedIp\\Honeypot\\Tests\\Unit\\';
                break;
            case 'Analyzers':
                $namespace = 'ReportedIp\\Honeypot\\Tests\\Analyzers\\';
                break;
            case 'Integration':
                $namespace = 'ReportedIp\\Honeypot\\Tests\\Integration\\';
                break;
            default:
                $namespace = 'ReportedIp\\Honeypot\\Tests\\';
                break;
        }

        $className = $namespace . $basename;

        if (class_exists($className)) {
            $framework->addTestClass($className);
            $classesLoaded++;
        } elseif ($verbose) {
            echo sprintf("  Warning: Class %s not found in %s\n", $className, $file);
        }
    }
}

if ($classesLoaded === 0) {
    echo "\n  No test classes found.\n";
    if ($filter !== null) {
        echo sprintf("  Filter applied: %s\n", $filter);
    }
    echo "\n";
    exit(1);
}

if ($verbose) {
    echo sprintf("\n  Loaded %d test class(es)\n", $classesLoaded);
}

$exitCode = $framework->execute();
exit($exitCode);
