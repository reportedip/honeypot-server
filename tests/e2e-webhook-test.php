<?php

declare(strict_types=1);

// E2E-Test: echter HTTP-Roundtrip Dispatcher -> lokaler Receiver.
// Voraussetzung: php -S 127.0.0.1:8765 tests/e2e-webhook-receiver.php läuft.

require __DIR__ . '/../src/Core/Config.php';

spl_autoload_register(static function (string $class): void {
    $prefix = 'ReportedIp\\Honeypot\\';
    if (str_starts_with($class, $prefix)) {
        $path = __DIR__ . '/../src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (file_exists($path)) {
            require_once $path;
        }
    }
});

use ReportedIp\Honeypot\Api\WebhookDispatcher;
use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\DetectionResult;
use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Persistence\WebhookRepository;

$captureFile = sys_get_temp_dir() . '/honeypot_webhook_capture.jsonl';
@unlink($captureFile);

$failures = [];
$check = static function (bool $cond, string $label) use (&$failures): void {
    echo($cond ? '  [PASS] ' : '  [FAIL] ') . $label . "\n";
    if (!$cond) {
        $failures[] = $label;
    }
};

$dbPath = sys_get_temp_dir() . '/honeypot_e2e_' . uniqid() . '.sqlite';
$db = new Database($dbPath);
$db->initialize();
$repo = new WebhookRepository($db);
$dispatcher = new WebhookDispatcher($repo, new Config([]));

$secret = 'e2e-test-secret';
$webhookId = $repo->add([
    'name'       => 'E2E Local Receiver',
    'url'        => 'http://127.0.0.1:8765/hook',
    'secret'     => $secret,
    'categories' => '16,18',
    'analyzers'  => '',
]);

// Nicht matchender Webhook darf nicht angesprochen werden
$nonMatchingId = $repo->add([
    'name'       => 'E2E Non-Matching',
    'url'        => 'http://127.0.0.1:8765/hook',
    'categories' => '29',
    'analyzers'  => 'Ransomware',
]);

echo "1. Detection-Dispatch (Kategorie 16 matcht Filter '16,18')...\n";

$request = new Request([
    'REQUEST_URI'    => '/wp-login.php?attack=1',
    'REQUEST_METHOD' => 'POST',
    'REMOTE_ADDR'    => '203.0.113.99',
    'HTTP_HOST'      => 'honeypot.example.com',
    'HTTP_USER_AGENT' => 'sqlmap/1.7',
]);
$request->setIp('203.0.113.99');

$results = [new DetectionResult([16, 45], 'SQL injection attempt detected', 85, 'SqlInjection')];
$delivered = $dispatcher->dispatch($request, $results);

$check($delivered === 1, "Genau 1 Webhook zugestellt (delivered={$delivered})");

$captured = file_exists($captureFile)
    ? array_map(static fn (string $l) => json_decode($l, true), array_filter(explode("\n", (string) file_get_contents($captureFile))))
    : [];

$check(count($captured) === 1, 'Receiver hat genau 1 Request erhalten (count=' . count($captured) . ')');

if (count($captured) === 1) {
    $rec = $captured[0];
    $payload = json_decode((string) $rec['body'], true);

    $check($rec['event'] === 'detection', 'X-ReportedIP-Event: detection');
    $check($rec['ctype'] === 'application/json', 'Content-Type: application/json');
    $check(str_starts_with((string) $rec['ua'], 'reportedip-honeypot-server/'), 'User-Agent enthält Versionspräfix (' . $rec['ua'] . ')');

    $expectedSig = 'sha256=' . hash_hmac('sha256', (string) $rec['body'], $secret);
    $check($rec['signature'] === $expectedSig, 'HMAC-SHA256-Signatur korrekt');

    $check(($payload['event'] ?? '') === 'detection', 'Payload: event=detection');
    $check(($payload['request']['ip'] ?? '') === '203.0.113.99', 'Payload: Angreifer-IP korrekt');
    $check(($payload['request']['uri'] ?? '') === '/wp-login.php?attack=1', 'Payload: URI korrekt');
    $check(($payload['detections'][0]['analyzer'] ?? '') === 'SqlInjection', 'Payload: Analyzer korrekt');
    $check(($payload['detections'][0]['categories'] ?? []) === [16, 45], 'Payload: Kategorien korrekt');
    $check(($payload['detections'][0]['category_names'][0] ?? '') === 'SQL Injection', 'Payload: Kategorie-Name aufgelöst');
    $check(($payload['detections'][0]['severity'] ?? 0) === 85, 'Payload: Severity korrekt');
    $check(($payload['honeypot']['host'] ?? '') === 'honeypot.example.com', 'Payload: Honeypot-Host korrekt');
}

$webhook = $repo->getById($webhookId);
$check(($webhook['last_status'] ?? '') === 'HTTP 200', "DB: last_status='HTTP 200' (ist: '{$webhook['last_status']}')");
$check((int) ($webhook['failure_count'] ?? -1) === 0, 'DB: failure_count=0');

$nonMatching = $repo->getById($nonMatchingId);
$check(($nonMatching['last_status'] ?? 'x') === '', 'Nicht matchender Webhook wurde nicht angesprochen');

echo "\n2. Test-Delivery (Admin-Button 'Test')...\n";
$testResult = $dispatcher->sendTest($repo->getById($webhookId));
$check($testResult['success'] === true, "sendTest erfolgreich (status: {$testResult['status']})");

$captured = array_map(static fn (string $l) => json_decode($l, true), array_filter(explode("\n", (string) file_get_contents($captureFile))));
$check(count($captured) === 2, 'Receiver hat den Test-Request erhalten');
if (count($captured) === 2) {
    $check($captured[1]['event'] === 'test', 'X-ReportedIP-Event: test');
}

echo "\n3. Fehlerfall (Endpoint nicht erreichbar)...\n";
$deadId = $repo->add(['name' => 'Dead', 'url' => 'http://127.0.0.1:9/hook']);
$deadResult = $dispatcher->sendTest($repo->getById($deadId));
$check($deadResult['success'] === false, 'Unerreichbarer Endpoint meldet Fehler');
$dead = $repo->getById($deadId);
$check((int) $dead['failure_count'] === 1, 'DB: failure_count inkrementiert');

@unlink($dbPath);
@unlink($captureFile);

echo "\n" . (empty($failures)
    ? "E2E-TEST BESTANDEN — alle Prüfungen erfolgreich.\n"
    : 'E2E-TEST FEHLGESCHLAGEN: ' . count($failures) . " Prüfungen fehlgeschlagen.\n");
exit(empty($failures) ? 0 : 1);
