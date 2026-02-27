<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests;

/**
 * Lightweight test framework for the honeypot project.
 *
 * Provides assertion helpers, test discovery, execution, and reporting
 * without requiring PHPUnit or any external testing dependency.
 */
final class TestFramework
{
    /** @var array<string, array{class: string, method: string}> */
    private array $tests = [];

    /** @var array<string, true> */
    private array $passed = [];

    /** @var array<string, string> */
    private array $failed = [];

    /** @var array<string, string> */
    private array $skipped = [];

    /** @var array<string, string> */
    private array $errors = [];

    private float $startTime = 0.0;
    private int $assertionCount = 0;
    private string $filter = '';
    private bool $verbose = false;

    public function setFilter(string $filter): void
    {
        $this->filter = $filter;
    }

    public function setVerbose(bool $verbose): void
    {
        $this->verbose = $verbose;
    }

    /**
     * Register a test case class. All public methods starting with 'test' are collected.
     */
    public function addTestClass(string $className): void
    {
        if (!class_exists($className)) {
            $this->errors[$className] = "Class {$className} does not exist";
            return;
        }

        $reflection = new \ReflectionClass($className);
        foreach ($reflection->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {
            if (strncmp($method->getName(), 'test', 4) === 0) {
                $testId = $className . '::' . $method->getName();

                if ($this->filter !== '' && stripos($testId, $this->filter) === false) {
                    continue;
                }

                $this->tests[$testId] = [
                    'class'  => $className,
                    'method' => $method->getName(),
                ];
            }
        }
    }

    /**
     * Static convenience: run an array of test class names.
     *
     * @param string[] $testClasses
     */
    public static function run(array $testClasses, string $filter = '', bool $verbose = false): int
    {
        $fw = new self();
        $fw->setFilter($filter);
        $fw->setVerbose($verbose);

        foreach ($testClasses as $className) {
            $fw->addTestClass($className);
        }

        return $fw->execute();
    }

    /**
     * Run all registered tests and return the exit code.
     */
    public function execute(): int
    {
        $this->startTime = microtime(true);

        echo sprintf("\n  Honeypot Test Suite\n  %s\n\n", str_repeat('=', 50));

        if ($this->filter !== '') {
            echo sprintf("  Filter: %s\n\n", $this->filter);
        }

        $currentClass = '';

        foreach ($this->tests as $testId => $test) {
            if ($test['class'] !== $currentClass) {
                $currentClass = $test['class'];
                echo sprintf("  %s\n", $this->shortClassName($currentClass));
            }

            $this->runTest($testId, $test['class'], $test['method']);
        }

        return $this->printSummary();
    }

    private function runTest(string $testId, string $className, string $methodName): void
    {
        $testStart = microtime(true);

        try {
            $instance = new $className($this);

            if (method_exists($instance, 'setUp')) {
                $instance->setUp();
            }

            $instance->$methodName();

            if (method_exists($instance, 'tearDown')) {
                $instance->tearDown();
            }

            $elapsed = microtime(true) - $testStart;
            $this->passed[$testId] = true;

            $timing = $this->verbose ? sprintf(' (%.1fms)', $elapsed * 1000) : '';
            echo sprintf("    \033[32m+\033[0m %s%s\n", $this->humanize($methodName), $timing);
        } catch (SkippedTestException $e) {
            $this->skipped[$testId] = $e->getMessage();
            echo sprintf("    \033[33m~\033[0m %s (skipped: %s)\n", $this->humanize($methodName), $e->getMessage());
        } catch (AssertionException $e) {
            $this->failed[$testId] = $e->getMessage();
            echo sprintf("    \033[31mx\033[0m %s\n      FAIL: %s\n", $this->humanize($methodName), $e->getMessage());
        } catch (\Throwable $e) {
            $this->errors[$testId] = sprintf('%s: %s in %s:%d', get_class($e), $e->getMessage(), $e->getFile(), $e->getLine());
            echo sprintf("    \033[31m!\033[0m %s\n      ERROR: %s\n", $this->humanize($methodName), $e->getMessage());
        }
    }

    private function printSummary(): int
    {
        $elapsed = microtime(true) - $this->startTime;
        $total = count($this->tests);
        $passedCount = count($this->passed);
        $failedCount = count($this->failed);
        $errorCount = count($this->errors);
        $skippedCount = count($this->skipped);

        echo sprintf("\n  %s\n", str_repeat('-', 50));
        echo sprintf("  Time: %.3f seconds, Assertions: %d\n\n", $elapsed, $this->assertionCount);

        if ($failedCount > 0) {
            echo "  \033[31mFailures:\033[0m\n";
            foreach ($this->failed as $tid => $msg) {
                echo sprintf("    - %s\n      %s\n", $tid, $msg);
            }
            echo "\n";
        }

        if ($errorCount > 0) {
            echo "  \033[31mErrors:\033[0m\n";
            foreach ($this->errors as $tid => $msg) {
                echo sprintf("    - %s\n      %s\n", $tid, $msg);
            }
            echo "\n";
        }

        $color = ($failedCount + $errorCount) === 0 ? '32' : '31';
        echo sprintf(
            "  \033[%sm%d passed, %d failed, %d errors, %d skipped (%d total)\033[0m\n\n",
            $color,
            $passedCount,
            $failedCount,
            $errorCount,
            $skippedCount,
            $total
        );

        return ($failedCount + $errorCount) > 0 ? 1 : 0;
    }

    // ========================
    // Assertion Methods
    // ========================

    public function assertTrue(bool $value, string $message = ''): void
    {
        $this->assertionCount++;
        if ($value !== true) {
            throw new AssertionException($message ?: 'Expected true, got false');
        }
    }

    public function assertFalse(bool $value, string $message = ''): void
    {
        $this->assertionCount++;
        if ($value !== false) {
            throw new AssertionException($message ?: 'Expected false, got true');
        }
    }

    /** @param mixed $expected @param mixed $actual */
    public function assertEquals($expected, $actual, string $message = ''): void
    {
        $this->assertionCount++;
        if ($expected !== $actual) {
            throw new AssertionException($message ?: sprintf('Expected %s, got %s', $this->export($expected), $this->export($actual)));
        }
    }

    /** @param mixed $expected @param mixed $actual */
    public function assertNotEquals($expected, $actual, string $message = ''): void
    {
        $this->assertionCount++;
        if ($expected === $actual) {
            throw new AssertionException($message ?: sprintf('Values should differ, both are %s', $this->export($expected)));
        }
    }

    /** @param mixed $value */
    public function assertNull($value, string $message = ''): void
    {
        $this->assertionCount++;
        if ($value !== null) {
            throw new AssertionException($message ?: sprintf('Expected null, got %s', $this->export($value)));
        }
    }

    /** @param mixed $value */
    public function assertNotNull($value, string $message = ''): void
    {
        $this->assertionCount++;
        if ($value === null) {
            throw new AssertionException($message ?: 'Expected non-null value, got null');
        }
    }

    /** @param mixed $object */
    public function assertInstanceOf(string $className, $object, string $message = ''): void
    {
        $this->assertionCount++;
        if (!($object instanceof $className)) {
            $actual = is_object($object) ? get_class($object) : gettype($object);
            throw new AssertionException($message ?: sprintf('Expected instance of %s, got %s', $className, $actual));
        }
    }

    public function assertContains(string $needle, string $haystack, string $message = ''): void
    {
        $this->assertionCount++;
        if (strpos($haystack, $needle) === false) {
            throw new AssertionException($message ?: sprintf('Expected string to contain "%s"', $needle));
        }
    }

    public function assertNotContains(string $needle, string $haystack, string $message = ''): void
    {
        $this->assertionCount++;
        if (strpos($haystack, $needle) !== false) {
            throw new AssertionException($message ?: sprintf('Expected string NOT to contain "%s"', $needle));
        }
    }

    public function assertStringContains(string $needle, string $haystack, string $message = ''): void
    {
        $this->assertionCount++;
        if (stripos($haystack, $needle) === false) {
            throw new AssertionException($message ?: sprintf('Expected string to contain "%s" (case-insensitive)', $needle));
        }
    }

    /** @param array<mixed>|\Countable $countable */
    public function assertCount(int $expected, $countable, string $message = ''): void
    {
        $this->assertionCount++;
        $actual = is_array($countable) ? count($countable) : (($countable instanceof \Countable) ? count($countable) : -1);
        if ($actual !== $expected) {
            throw new AssertionException($message ?: sprintf('Expected count %d, got %d', $expected, $actual));
        }
    }

    public function assertGreaterThan(int $expected, int $actual, string $message = ''): void
    {
        $this->assertionCount++;
        if ($actual <= $expected) {
            throw new AssertionException($message ?: sprintf('Expected > %d, got %d', $expected, $actual));
        }
    }

    public function assertGreaterThanOrEqual(int $expected, int $actual, string $message = ''): void
    {
        $this->assertionCount++;
        if ($actual < $expected) {
            throw new AssertionException($message ?: sprintf('Expected >= %d, got %d', $expected, $actual));
        }
    }

    public function assertLessThanOrEqual(int $expected, int $actual, string $message = ''): void
    {
        $this->assertionCount++;
        if ($actual > $expected) {
            throw new AssertionException($message ?: sprintf('Expected <= %d, got %d', $expected, $actual));
        }
    }

    /** @param array<mixed> $array */
    public function assertArrayHasKey(string $key, array $array, string $message = ''): void
    {
        $this->assertionCount++;
        if (!array_key_exists($key, $array)) {
            throw new AssertionException($message ?: sprintf('Expected array to have key "%s"', $key));
        }
    }

    /** @param mixed $value */
    public function assertNotEmpty($value, string $message = ''): void
    {
        $this->assertionCount++;
        if (empty($value)) {
            throw new AssertionException($message ?: 'Expected non-empty value');
        }
    }

    /** @param mixed $value */
    public function assertEmpty($value, string $message = ''): void
    {
        $this->assertionCount++;
        if (!empty($value)) {
            throw new AssertionException($message ?: sprintf('Expected empty value, got %s', $this->export($value)));
        }
    }

    public function assertMatchesRegex(string $pattern, string $string, string $message = ''): void
    {
        $this->assertionCount++;
        if (!preg_match($pattern, $string)) {
            throw new AssertionException($message ?: sprintf('Expected string to match pattern %s', $pattern));
        }
    }

    public function skip(string $reason = ''): void
    {
        throw new SkippedTestException($reason ?: 'Test skipped');
    }

    // ========================
    // Helpers
    // ========================

    /** @param mixed $value */
    private function export($value): string
    {
        if (is_string($value)) {
            $d = strlen($value) > 80 ? substr($value, 0, 80) . '...' : $value;
            return '"' . $d . '"';
        }
        if (is_array($value)) {
            return 'array(' . count($value) . ')';
        }
        if (is_object($value)) {
            return get_class($value);
        }
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if ($value === null) {
            return 'null';
        }
        return (string) $value;
    }

    private function humanize(string $methodName): string
    {
        $name = (string) preg_replace('/^test_?/', '', $methodName);
        $name = (string) preg_replace('/([A-Z])/', ' $1', $name);
        return trim(strtolower($name));
    }

    private function shortClassName(string $className): string
    {
        $parts = explode('\\', $className);
        return end($parts);
    }
}

/**
 * Base class for all test cases.
 */
abstract class TestCase
{
    protected TestFramework $t;

    public function __construct(TestFramework $framework)
    {
        $this->t = $framework;
    }

    public function setUp(): void
    {
    }

    public function tearDown(): void
    {
    }

    /**
     * Create a Request object for testing with sensible defaults.
     *
     * @param array<string, mixed> $overrides Keys: uri, method, headers, body, postData, queryParams, ip, cookies
     */
    protected function createRequest(array $overrides = []): \ReportedIp\Honeypot\Core\Request
    {
        $defaults = [
            'uri'         => '/',
            'method'      => 'GET',
            'headers'     => ['Host' => 'example.com', 'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'],
            'body'        => '',
            'postData'    => [],
            'queryParams' => [],
            'ip'          => '1.2.3.4',
            'cookies'     => [],
        ];

        $opts = array_merge($defaults, $overrides);

        // Merge headers rather than replacing entirely
        if (isset($overrides['headers'])) {
            $opts['headers'] = array_merge($defaults['headers'], $overrides['headers']);
        }

        $server = [
            'REQUEST_URI'    => $opts['uri'],
            'REQUEST_METHOD' => strtoupper($opts['method']),
            'REMOTE_ADDR'    => $opts['ip'],
        ];

        foreach ($opts['headers'] as $name => $value) {
            $serverKey = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
            $server[$serverKey] = $value;
        }

        if (isset($opts['headers']['Content-Type'])) {
            $server['CONTENT_TYPE'] = $opts['headers']['Content-Type'];
        }

        $queryParams = $opts['queryParams'];
        if (empty($queryParams)) {
            $qs = parse_url($opts['uri'], PHP_URL_QUERY);
            if ($qs !== null && $qs !== false) {
                parse_str($qs, $queryParams);
            }
        }

        return new \ReportedIp\Honeypot\Core\Request(
            $server,
            $queryParams,
            $opts['postData'],
            $opts['cookies'],
            $opts['body']
        );
    }
}

class AssertionException extends \RuntimeException
{
}

class SkippedTestException extends \RuntimeException
{
}
