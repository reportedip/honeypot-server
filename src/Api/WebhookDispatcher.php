<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Api;

use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Core\Version;
use ReportedIp\Honeypot\Detection\CategoryRegistry;
use ReportedIp\Honeypot\Detection\DetectionResult;
use ReportedIp\Honeypot\Persistence\WebhookRepository;

/**
 * Dispatches detection events to user-configured webhook endpoints.
 *
 * Lets honeypot operators forward detections to their own logging or
 * SIEM systems in real time. Each webhook can filter by category IDs
 * and/or analyzer names (OR semantics; empty filters match everything).
 * Payloads are JSON; with a configured secret each request carries an
 * HMAC-SHA256 signature in the X-ReportedIP-Signature header.
 */
final class WebhookDispatcher
{
    private const TIMEOUT_SECONDS = 5;
    private const CONNECT_TIMEOUT_SECONDS = 3;

    public function __construct(
        private readonly WebhookRepository $repository,
        private readonly Config $config
    ) {
    }

    /**
     * Dispatch detections to all matching enabled webhooks.
     *
     * @param DetectionResult[] $results
     * @return int Number of successfully delivered webhooks.
     */
    public function dispatch(Request $request, array $results): int
    {
        if (empty($results)) {
            return 0;
        }

        $delivered = 0;

        foreach ($this->repository->getEnabled() as $webhook) {
            $matching = array_values(array_filter(
                $results,
                static fn (DetectionResult $r): bool => self::shouldTrigger($webhook, $r)
            ));

            if (empty($matching)) {
                continue;
            }

            $payload = $this->buildPayload($request, $matching);
            $outcome = $this->deliver($webhook, $payload, 'detection');

            $this->repository->recordResult((int) $webhook['id'], $outcome['success'], $outcome['status']);

            if ($outcome['success']) {
                $delivered++;
            }
        }

        return $delivered;
    }

    /**
     * Check whether a webhook's filters match a detection result.
     *
     * Empty filters match everything. When both filters are set,
     * either one matching triggers the webhook (OR semantics).
     *
     * @param array<string, mixed> $webhook Row from honeypot_webhooks.
     */
    public static function shouldTrigger(array $webhook, DetectionResult $result): bool
    {
        $categoryFilter = self::parseCsv((string) ($webhook['categories'] ?? ''));
        $analyzerFilter = self::parseCsv((string) ($webhook['analyzers'] ?? ''));

        if (empty($categoryFilter) && empty($analyzerFilter)) {
            return true;
        }

        if (!empty($categoryFilter)) {
            $categoryIds = array_map('intval', $categoryFilter);
            if (array_intersect($result->getCategories(), $categoryIds) !== []) {
                return true;
            }
        }

        if (!empty($analyzerFilter) && in_array($result->getAnalyzerName(), $analyzerFilter, true)) {
            return true;
        }

        return false;
    }

    /**
     * Build the JSON payload for a detection event.
     *
     * @param DetectionResult[] $results
     * @return array<string, mixed>
     */
    public function buildPayload(Request $request, array $results): array
    {
        $detections = [];
        foreach ($results as $result) {
            $detections[] = [
                'analyzer'       => $result->getAnalyzerName(),
                'categories'     => $result->getCategories(),
                'category_names' => array_map(
                    static fn (int $id): string => CategoryRegistry::getName($id),
                    $result->getCategories()
                ),
                'comment'        => $result->getComment(),
                'severity'       => $result->getScore(),
            ];
        }

        return [
            'event'        => 'detection',
            'generated_at' => gmdate('c'),
            'honeypot'     => [
                'name'    => 'reportedip-honeypot-server',
                'version' => $this->getVersion(),
                'host'    => (string) ($request->getHeader('Host') ?? ''),
                'profile' => (string) $this->config->get('cms_profile', 'wordpress'),
            ],
            'request'      => [
                'ip'         => $request->getIp(),
                'method'     => $request->getMethod(),
                'uri'        => $request->getUri(),
                'user_agent' => $request->getUserAgent(),
            ],
            'detections'   => $detections,
        ];
    }

    /**
     * Send a test event to verify a webhook configuration.
     *
     * @param array<string, mixed> $webhook Row from honeypot_webhooks.
     * @return array{success: bool, status: string}
     */
    public function sendTest(array $webhook): array
    {
        $payload = [
            'event'        => 'test',
            'generated_at' => gmdate('c'),
            'honeypot'     => [
                'name'    => 'reportedip-honeypot-server',
                'version' => $this->getVersion(),
            ],
            'message'      => 'Test delivery from ReportedIP Honeypot webhook configuration.',
        ];

        $outcome = $this->deliver($webhook, $payload, 'test');
        $this->repository->recordResult((int) $webhook['id'], $outcome['success'], $outcome['status']);

        return $outcome;
    }

    /**
     * Compute the signature header value for a payload body.
     */
    public static function sign(string $body, string $secret): string
    {
        return 'sha256=' . hash_hmac('sha256', $body, $secret);
    }

    /**
     * POST a payload to a webhook endpoint.
     *
     * @param array<string, mixed> $webhook
     * @param array<string, mixed> $payload
     * @return array{success: bool, status: string}
     */
    private function deliver(array $webhook, array $payload, string $event): array
    {
        $body = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if ($body === false) {
            return ['success' => false, 'status' => 'JSON encoding failed'];
        }

        $headers = [
            'Content-Type: application/json',
            'User-Agent: reportedip-honeypot-server/' . $this->getVersion(),
            'X-ReportedIP-Event: ' . $event,
        ];

        $secret = (string) ($webhook['secret'] ?? '');
        if ($secret !== '') {
            $headers[] = 'X-ReportedIP-Signature: ' . self::sign($body, $secret);
        }

        $ch = curl_init();
        if ($ch === false) {
            return ['success' => false, 'status' => 'cURL init failed'];
        }

        $curlOpts = [
            CURLOPT_URL            => (string) $webhook['url'],
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $body,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => self::TIMEOUT_SECONDS,
            CURLOPT_CONNECTTIMEOUT => self::CONNECT_TIMEOUT_SECONDS,
            CURLOPT_HTTPHEADER     => $headers,
        ];

        $caBundle = (string) $this->config->get('ca_bundle', '');
        if ($caBundle !== '' && file_exists($caBundle)) {
            $curlOpts[CURLOPT_CAINFO] = $caBundle;
        }

        curl_setopt_array($ch, $curlOpts);

        $response = curl_exec($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($curlError !== '') {
            return ['success' => false, 'status' => 'cURL error: ' . $curlError];
        }

        if ($httpCode >= 200 && $httpCode < 300) {
            return ['success' => true, 'status' => 'HTTP ' . $httpCode];
        }

        return ['success' => false, 'status' => 'HTTP ' . $httpCode];
    }

    /**
     * Get the current application version.
     */
    private function getVersion(): string
    {
        return Version::current();
    }

    /**
     * @return string[]
     */
    private static function parseCsv(string $csv): array
    {
        if (trim($csv) === '') {
            return [];
        }
        return array_values(array_filter(array_map('trim', explode(',', $csv)), static fn (string $v): bool => $v !== ''));
    }
}
