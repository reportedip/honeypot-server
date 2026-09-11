<?php

declare(strict_types=1);

/**
 * End-to-End test suite against the Docker honeypot instance.
 *
 * Usage: php tests/e2e-docker-test.php [base_url]
 */

$baseUrl = $argv[1] ?? 'http://localhost:8098';

echo "=== Running E2E Docker Tests against {$baseUrl} ===\n\n";

$dbPath = __DIR__ . '/../data/honeypot.sqlite';
if (!file_exists($dbPath)) {
    echo "ERROR: SQLite database not found at {$dbPath}\n";
    exit(1);
}

function sendRequest(string $url, string $userAgent, array $headers = []): array
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER         => true,
        CURLOPT_USERAGENT      => $userAgent,
        CURLOPT_TIMEOUT        => 5,
        CURLOPT_HTTPHEADER     => $headers,
    ]);
    $raw = curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    curl_close($ch);

    return [
        'status' => $status,
        'body'   => substr((string) $raw, $headerSize),
    ];
}

$passed = 0;
$failed = 0;

function assertCondition(bool $condition, string $label, string $details = ''): void
{
    global $passed, $failed;
    if ($condition) {
        echo "  [PASS] {$label}\n";
        $passed++;
    } else {
        echo "  [FAIL] {$label}" . ($details !== '' ? " ({$details})" : '') . "\n";
        $failed++;
    }
}

// Prepare unique test IPs
$ipOai = '198.51.100.' . random_int(1, 250);
$ipHuman = '198.51.100.' . random_int(1, 250);
$ipSpider = '198.51.100.' . random_int(1, 250);
$ipSqli = '198.51.100.' . random_int(1, 250);

$uaOai = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36; compatible; OAI-SearchBot/1.4; robots.txt; +https://openai.com/searchbot';
$uaChrome = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

// -------------------------------------------------------------
// Step 1: Send all HTTP requests to Docker container
// (Keep SQLite closed on host to avoid Windows file locks)
// -------------------------------------------------------------
echo "1. Sending HTTP requests to honeypot in Docker...\n";

$resOai = sendRequest("{$baseUrl}/robots.txt", $uaOai, ["X-Forwarded-For: {$ipOai}"]);
assertCondition($resOai['status'] === 200, 'OAI-SearchBot: HTTP status is 200 OK');
assertCondition(str_contains($resOai['body'], 'User-agent: *'), 'OAI-SearchBot: Response contains robots.txt');

$resHuman = sendRequest("{$baseUrl}/robots.txt", $uaChrome, ["X-Forwarded-For: {$ipHuman}"]);
assertCondition($resHuman['status'] === 200, 'Human browser: HTTP status is 200 OK');

$resSpider = sendRequest("{$baseUrl}/wp-admin-backup-9f3a2c/", $uaChrome, ["X-Forwarded-For: {$ipSpider}"]);
assertCondition(in_array($resSpider['status'], [301, 302, 404, 200], true), 'Spider trap bait path: HTTP handled');

$resSqli = sendRequest("{$baseUrl}/robots.txt?id=1%27%20UNION%20SELECT%201,2,3--", $uaChrome, ["X-Forwarded-For: {$ipSqli}"]);
assertCondition($resSqli['status'] === 200, 'SQL injection attempt: HTTP handled');

// -------------------------------------------------------------
// Step 2: Allow background queue/flush to write to SQLite
// -------------------------------------------------------------
echo "\n2. Waiting for Docker container to complete background logging...\n";
sleep(1);

// -------------------------------------------------------------
// Step 3: Open SQLite and verify recorded data
// -------------------------------------------------------------
echo "\n3. Verifying database records...\n";
$db = new PDO("sqlite:{$dbPath}");
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Verify OAI-SearchBot
$stmt = $db->prepare('SELECT * FROM honeypot_visitors WHERE ip = ? ORDER BY id DESC LIMIT 1');
$stmt->execute([$ipOai]);
$visOai = $stmt->fetch(PDO::FETCH_ASSOC);

assertCondition($visOai !== false, 'OAI-SearchBot: Visitor logged to honeypot_visitors');
assertCondition(($visOai['visitor_type'] ?? '') === 'ai_agent', 'OAI-SearchBot: visitor_type is "ai_agent"', 'got: ' . ($visOai['visitor_type'] ?? 'none'));
assertCondition(($visOai['bot_name'] ?? '') === 'OpenAI SearchBot', 'OAI-SearchBot: bot_name is "OpenAI SearchBot"', 'got: ' . ($visOai['bot_name'] ?? 'none'));

$stmt = $db->prepare('SELECT * FROM honeypot_logs WHERE ip = ?');
$stmt->execute([$ipOai]);
$logsOai = $stmt->fetchAll(PDO::FETCH_ASSOC);
assertCondition(count($logsOai) === 0, 'OAI-SearchBot: No false positive threat logs generated');

// Verify Human Browser on robots.txt
$stmt = $db->prepare('SELECT * FROM honeypot_visitors WHERE ip = ? ORDER BY id DESC LIMIT 1');
$stmt->execute([$ipHuman]);
$visHuman = $stmt->fetch(PDO::FETCH_ASSOC);

assertCondition($visHuman !== false, 'Human browser: Visitor logged to honeypot_visitors');
assertCondition(($visHuman['visitor_type'] ?? '') === 'human', 'Human browser: visitor_type is "human" (NOT hacker)', 'got: ' . ($visHuman['visitor_type'] ?? 'none'));

$stmt = $db->prepare('SELECT * FROM honeypot_logs WHERE ip = ?');
$stmt->execute([$ipHuman]);
$logsHuman = $stmt->fetchAll(PDO::FETCH_ASSOC);
assertCondition(count($logsHuman) === 0, 'Human browser: No false PathScanning threat logs generated');

// Verify Spider Trap Detection
$stmt = $db->prepare('SELECT * FROM honeypot_logs WHERE ip = ? ORDER BY id DESC LIMIT 1');
$stmt->execute([$ipSpider]);
$logSpider = $stmt->fetch(PDO::FETCH_ASSOC);

assertCondition($logSpider !== false, 'Spider trap: Detection recorded in honeypot_logs');
assertCondition(str_contains($logSpider['comment'] ?? '', 'Spider trap'), 'Spider trap: Detection comment mentions Spider trap');
assertCondition(str_contains($logSpider['categories'] ?? '', '63'), 'Spider trap: Includes Category 63');

$stmt = $db->prepare('SELECT * FROM honeypot_visitors WHERE ip = ? ORDER BY id DESC LIMIT 1');
$stmt->execute([$ipSpider]);
$visSpider = $stmt->fetch(PDO::FETCH_ASSOC);
assertCondition($visSpider !== false, 'Spider trap: Visitor logged');
assertCondition(($visSpider['visitor_type'] ?? '') === 'hacker', 'Spider trap: Visitor hitting bait path is classified as "hacker"');

// Verify SQL Injection Detection
$stmt = $db->prepare('SELECT * FROM honeypot_logs WHERE ip = ? ORDER BY id DESC LIMIT 1');
$stmt->execute([$ipSqli]);
$logSqli = $stmt->fetch(PDO::FETCH_ASSOC);

assertCondition($logSqli !== false, 'SQL injection: Attack detection recorded in honeypot_logs');
assertCondition(str_contains($logSqli['comment'] ?? '', 'SQL'), 'SQL injection: Comment indicates SQL pattern');

$stmt = $db->prepare('SELECT * FROM honeypot_visitors WHERE ip = ? ORDER BY id DESC LIMIT 1');
$stmt->execute([$ipSqli]);
$visSqli = $stmt->fetch(PDO::FETCH_ASSOC);
assertCondition($visSqli !== false, 'SQL injection: Visitor logged');
assertCondition(($visSqli['visitor_type'] ?? '') === 'hacker', 'SQL injection: Attacker is classified as "hacker"');

// Close DB
$db = null;

// -------------------------------------------------------------
// Summary
// -------------------------------------------------------------
echo "\n=== E2E Test Results: {$passed} passed, {$failed} failed ===\n";
exit($failed > 0 ? 1 : 0);
