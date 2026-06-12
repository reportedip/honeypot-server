<?php

declare(strict_types=1);

// Minimaler Webhook-Receiver für den E2E-Test.
// Schreibt Body + relevante Header als JSON-Zeile in die Capture-Datei.

$captureFile = sys_get_temp_dir() . '/honeypot_webhook_capture.jsonl';

$customHeaders = [];
foreach ($_SERVER as $key => $value) {
    if (str_starts_with($key, 'HTTP_')) {
        $customHeaders[str_replace('_', '-', substr($key, 5))] = $value;
    }
}

$record = [
    'body'      => file_get_contents('php://input'),
    'event'     => $_SERVER['HTTP_X_REPORTEDIP_EVENT'] ?? '',
    'signature' => $_SERVER['HTTP_X_REPORTEDIP_SIGNATURE'] ?? '',
    'ua'        => $_SERVER['HTTP_USER_AGENT'] ?? '',
    'ctype'     => $_SERVER['CONTENT_TYPE'] ?? '',
    'headers'   => $customHeaders,
    'method'    => $_SERVER['REQUEST_METHOD'] ?? '',
    'uri'       => $_SERVER['REQUEST_URI'] ?? '',
];

file_put_contents($captureFile, json_encode($record) . "\n", FILE_APPEND | LOCK_EX);

http_response_code(200);
header('Content-Type: application/json');
echo '{"received":true}';
