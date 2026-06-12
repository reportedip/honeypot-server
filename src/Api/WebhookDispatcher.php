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

    private const ALLOWED_METHODS = ['POST', 'PUT', 'PATCH', 'GET'];

    /**
     * Mapping reportedip.de category IDs -> AbuseIPDB category IDs.
     *
     * IDs 1-23 are identical on both platforms; the CMS-specific
     * categories 24-58 are translated to their closest equivalent.
     *
     * @var array<int, int[]>
     */
    private const ABUSEIPDB_MAP = [
        24 => [15],     // Cryptomining -> Hacking
        25 => [19],     // Data Harvesting -> Bad Web Bot
        26 => [20],     // Malware Hosting -> Exploited Host
        27 => [20],     // Command & Control -> Exploited Host
        28 => [15],     // Backdoor Access -> Hacking
        29 => [15],     // Ransomware -> Hacking
        30 => [15],     // Malware Upload -> Hacking
        31 => [18, 21], // WP Login Brute Force -> Brute-Force + Web App Attack
        32 => [21],     // WP Admin Probe -> Web App Attack
        33 => [21],     // WP XML-RPC Abuse -> Web App Attack
        34 => [21],     // WP REST API Abuse -> Web App Attack
        35 => [21],     // WP Vulnerability Scan -> Web App Attack
        36 => [21],     // WP Theme Exploit -> Web App Attack
        37 => [21],     // WP Core File Modification -> Web App Attack
        38 => [21],     // WP Config Exposure -> Web App Attack
        39 => [21],     // WP Database Exposure -> Web App Attack
        40 => [10],     // WP Form Spam -> Web Spam
        41 => [10],     // WP Registration Spam -> Web Spam
        42 => [12],     // WP Trackback Spam -> Blog Spam
        43 => [21],     // WP File Upload Attack -> Web App Attack
        44 => [21],     // Cross-Site Scripting -> Web App Attack
        45 => [21],     // Code Injection -> Web App Attack
        46 => [21],     // WP Core Tampering -> Web App Attack
        47 => [21],     // Directory Traversal -> Web App Attack
        48 => [21],     // File Inclusion -> Web App Attack
        49 => [19],     // Scraping -> Bad Web Bot
        50 => [21],     // Open Redirect -> Web App Attack
        51 => [4],      // Resource Exhaustion -> DDoS Attack
        52 => [21],     // Media Library Abuse -> Web App Attack
        53 => [10],     // Search Spam -> Web Spam
        54 => [21],     // WP Cron Abuse -> Web App Attack
        55 => [21],     // User Enumeration -> Web App Attack
        56 => [14],     // Version Fingerprinting -> Port Scan
        57 => [21],     // WP Plugin Exploit -> Web App Attack
        58 => [21],     // Config File Exposure -> Web App Attack
    ];

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
            $fields = $this->buildFields($request, $matching);
            $outcome = $this->deliver($webhook, $payload, $fields, 'detection');

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

        // Beispieldaten für form/custom-Templates. Die Loopback-IP sorgt
        // dafür, dass externe Abuse-APIs den Testreport ablehnen statt
        // einen echten Report zu erzeugen.
        $fields = [
            'event'                => 'test',
            'ip'                   => '127.0.0.1',
            'categories'           => '15,21',
            'abuseipdb_categories' => '15,21',
            'comment'              => '[Test] Test delivery from ReportedIP Honeypot webhook configuration.',
            'severity'             => '50',
            'analyzers'            => 'Test',
            'uri'                  => '/test',
            'method'               => 'GET',
            'user_agent'           => 'test-agent',
            'host'                 => '',
            'timestamp'            => gmdate('c'),
            'version'              => $this->getVersion(),
        ];

        $outcome = $this->deliver($webhook, $payload, $fields, 'test');
        $this->repository->recordResult((int) $webhook['id'], $outcome['success'], $outcome['status']);

        return $outcome;
    }

    /**
     * Build the flat field map used for form bodies and custom templates.
     *
     * Multiple detections are aggregated: categories are merged, the
     * severity is the maximum, comments are joined.
     *
     * @param DetectionResult[] $results
     * @return array<string, string>
     */
    public function buildFields(Request $request, array $results): array
    {
        $categories = [];
        $analyzers = [];
        $comments = [];
        $severity = 0;

        foreach ($results as $result) {
            $categories = array_merge($categories, $result->getCategories());
            $analyzers[] = $result->getAnalyzerName();
            $comments[] = sprintf('[%s] %s', $result->getAnalyzerName(), $result->getComment());
            $severity = max($severity, $result->getScore());
        }

        $categories = array_values(array_unique($categories));
        sort($categories);
        $analyzers = array_values(array_unique($analyzers));
        sort($analyzers);

        return [
            'event'                => 'detection',
            'ip'                   => $request->getIp(),
            'categories'           => implode(',', $categories),
            'abuseipdb_categories' => implode(',', self::mapCategoriesToAbuseIpDb($categories)),
            'comment'              => implode(' | ', $comments),
            'severity'             => (string) $severity,
            'analyzers'            => implode(',', $analyzers),
            'uri'                  => $request->getUri(),
            'method'               => $request->getMethod(),
            'user_agent'           => $request->getUserAgent(),
            'host'                 => (string) ($request->getHeader('Host') ?? ''),
            'timestamp'            => gmdate('c'),
            'version'              => $this->getVersion(),
        ];
    }

    /**
     * Map reportedip.de category IDs to AbuseIPDB category IDs.
     *
     * IDs 1-23 pass through unchanged; CMS-specific IDs are translated;
     * unknown IDs fall back to 21 (Web App Attack).
     *
     * @param int[] $categories
     * @return int[] Sorted, deduplicated AbuseIPDB category IDs.
     */
    public static function mapCategoriesToAbuseIpDb(array $categories): array
    {
        $mapped = [];
        foreach ($categories as $id) {
            $id = (int) $id;
            if ($id >= 1 && $id <= 23) {
                $mapped[] = $id;
            } else {
                $mapped = array_merge($mapped, self::ABUSEIPDB_MAP[$id] ?? [21]);
            }
        }

        $mapped = array_values(array_unique($mapped));
        sort($mapped);
        return $mapped;
    }

    /**
     * Render a body or URL template by replacing {{placeholder}} tokens.
     *
     * For every field three variants exist: {{name}} (raw),
     * {{name_url}} (rawurlencode) and {{name_json}} (JSON-escaped,
     * without surrounding quotes). Unknown placeholders are left as-is.
     *
     * @param array<string, string> $fields
     */
    public static function renderTemplate(string $template, array $fields): string
    {
        return (string) preg_replace_callback(
            '/\{\{([a-z0-9_]+)\}\}/i',
            static function (array $m) use ($fields): string {
                $key = $m[1];

                if (str_ends_with($key, '_url')) {
                    $base = substr($key, 0, -4);
                    if (array_key_exists($base, $fields)) {
                        return rawurlencode($fields[$base]);
                    }
                } elseif (str_ends_with($key, '_json')) {
                    $base = substr($key, 0, -5);
                    if (array_key_exists($base, $fields)) {
                        $encoded = json_encode($fields[$base], JSON_UNESCAPED_SLASHES);
                        return $encoded === false ? '' : substr($encoded, 1, -1);
                    }
                } elseif (array_key_exists($key, $fields)) {
                    return $fields[$key];
                }

                return $m[0];
            },
            $template
        );
    }

    /**
     * Parse user-configured header lines ("Name: Value", one per line).
     *
     * Invalid lines are dropped; values cannot contain CR/LF because
     * each line is parsed individually.
     *
     * @return string[] Normalized "Name: Value" strings.
     */
    public static function parseHeaderLines(string $headers): array
    {
        $result = [];
        foreach (preg_split('/\r\n|\r|\n/', $headers) ?: [] as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            if (preg_match('/^([A-Za-z0-9-]+):\s*(.+)$/', $line, $m)) {
                $result[] = $m[1] . ': ' . trim($m[2]);
            }
        }
        return $result;
    }

    /**
     * Compute the signature header value for a payload body.
     */
    public static function sign(string $body, string $secret): string
    {
        return 'sha256=' . hash_hmac('sha256', $body, $secret);
    }

    /**
     * Send a payload to a webhook endpoint using its configured
     * method, headers, and body format.
     *
     * @param array<string, mixed>  $webhook
     * @param array<string, mixed>  $payload JSON payload (body_format=json).
     * @param array<string, string> $fields  Flat fields (form/custom + URL templates).
     * @return array{success: bool, status: string}
     */
    private function deliver(array $webhook, array $payload, array $fields, string $event): array
    {
        $format = (string) ($webhook['body_format'] ?? 'json');
        $method = strtoupper(trim((string) ($webhook['method'] ?? 'POST')));
        if (!in_array($method, self::ALLOWED_METHODS, true)) {
            $method = 'POST';
        }

        // Build the body according to the configured format
        $contentType = 'application/json';
        if ($format === 'form') {
            $body = http_build_query($fields);
            $contentType = 'application/x-www-form-urlencoded';
        } elseif ($format === 'custom') {
            $body = self::renderTemplate((string) ($webhook['body_template'] ?? ''), $fields);
            $contentType = str_starts_with(ltrim($body), '{') || str_starts_with(ltrim($body), '[')
                ? 'application/json'
                : 'application/x-www-form-urlencoded';
        } else {
            $encoded = json_encode($payload, JSON_UNESCAPED_SLASHES);
            if ($encoded === false) {
                return ['success' => false, 'status' => 'JSON encoding failed'];
            }
            $body = $encoded;
        }

        // GET requests carry no body — data goes into the URL template
        if ($method === 'GET') {
            $body = '';
        }

        // Default headers, overridable by user-configured ones
        $headerMap = [
            'content-type'        => 'Content-Type: ' . $contentType,
            'user-agent'          => 'User-Agent: reportedip-honeypot-server/' . $this->getVersion(),
            'x-reportedip-event'  => 'X-ReportedIP-Event: ' . $event,
        ];

        foreach (self::parseHeaderLines((string) ($webhook['headers'] ?? '')) as $line) {
            $name = strtolower((string) strstr($line, ':', true));
            $headerMap[$name] = $line;
        }

        $secret = (string) ($webhook['secret'] ?? '');
        if ($secret !== '') {
            $headerMap['x-reportedip-signature'] = 'X-ReportedIP-Signature: ' . self::sign($body, $secret);
        }

        // Placeholders in the URL allow GET-style APIs
        $url = self::renderTemplate((string) $webhook['url'], $fields);

        $ch = curl_init();
        if ($ch === false) {
            return ['success' => false, 'status' => 'cURL init failed'];
        }

        $curlOpts = [
            CURLOPT_URL            => $url,
            CURLOPT_CUSTOMREQUEST  => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => self::TIMEOUT_SECONDS,
            CURLOPT_CONNECTTIMEOUT => self::CONNECT_TIMEOUT_SECONDS,
            CURLOPT_HTTPHEADER     => array_values($headerMap),
        ];

        if ($method !== 'GET') {
            $curlOpts[CURLOPT_POSTFIELDS] = $body;
        }

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
