<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Core;

/**
 * HTTP request wrapper.
 *
 * Encapsulates superglobals into an immutable object for safe passing
 * through the detection pipeline and trap rendering.
 */
final class Request
{
    private string $uri;
    private string $method;
    /** @var array<string, string> */
    private array $headers;
    private string $body;
    /** @var array<string, mixed> */
    private array $postData;
    /** @var array<string, string> */
    private array $queryParams;
    /** @var array<string, string> */
    private array $cookies;
    /** @var array<string, mixed> */
    private array $server;
    private string $ip;

    /**
     * @param array<string, mixed> $server
     * @param array<string, string> $queryParams
     * @param array<string, mixed> $postData
     * @param array<string, string> $cookies
     * @param string $body
     */
    public function __construct(
        array $server,
        array $queryParams = [],
        array $postData = [],
        array $cookies = [],
        string $body = ''
    ) {
        $this->server = $server;
        $this->uri = (string) ($server['REQUEST_URI'] ?? '/');
        $this->method = strtoupper((string) ($server['REQUEST_METHOD'] ?? 'GET'));
        $this->headers = $this->extractHeaders($server);
        $this->body = $body;
        $this->postData = $postData;
        $this->queryParams = $queryParams;
        $this->cookies = $cookies;
        $this->ip = (string) ($server['REMOTE_ADDR'] ?? '0.0.0.0');
    }

    /**
     * Create a Request from PHP superglobals.
     */
    public static function fromGlobals(): self
    {
        $body = (string) file_get_contents('php://input');

        return new self(
            $_SERVER,
            $_GET,
            $_POST,
            $_COOKIE,
            $body
        );
    }

    /**
     * Get the full request URI including query string.
     */
    public function getUri(): string
    {
        return $this->uri;
    }

    /**
     * Get the path component without query string.
     */
    public function getPath(): string
    {
        $path = parse_url($this->uri, PHP_URL_PATH);
        return $path !== false && $path !== null ? $path : '/';
    }

    /**
     * Get the HTTP method (uppercase).
     */
    public function getMethod(): string
    {
        return $this->method;
    }

    /**
     * Get all HTTP request headers.
     *
     * @return array<string, string>
     */
    public function getHeaders(): array
    {
        return $this->headers;
    }

    /**
     * Get a single header value by name (case-insensitive).
     */
    public function getHeader(string $name): ?string
    {
        $lower = strtolower($name);
        foreach ($this->headers as $key => $value) {
            if (strtolower($key) === $lower) {
                return $value;
            }
        }
        return null;
    }

    /**
     * Get the raw request body.
     */
    public function getBody(): string
    {
        return $this->body;
    }

    /**
     * Get POST data.
     *
     * @return array<string, mixed>
     */
    public function getPostData(): array
    {
        return $this->postData;
    }

    /**
     * Get all query parameters.
     *
     * @return array<string, string>
     */
    public function getQueryParams(): array
    {
        return $this->queryParams;
    }

    /**
     * Get a single query parameter by name.
     */
    public function getQueryParam(string $name): ?string
    {
        return $this->queryParams[$name] ?? null;
    }

    /**
     * Get all cookies.
     *
     * @return array<string, string>
     */
    public function getCookies(): array
    {
        return $this->cookies;
    }

    /**
     * Get the User-Agent string.
     */
    public function getUserAgent(): string
    {
        return $this->getHeader('User-Agent') ?? '';
    }

    /**
     * Get the resolved client IP address.
     */
    public function getIp(): string
    {
        return $this->ip;
    }

    /**
     * Set the resolved client IP address (called by IpResolver).
     */
    public function setIp(string $ip): void
    {
        $this->ip = $ip;
    }

    /**
     * Get the base URL (scheme + host) derived from the current request.
     */
    public function getBaseUrl(): string
    {
        $scheme = 'http';
        if ((!empty($this->server['HTTPS']) && $this->server['HTTPS'] !== 'off')
            || $this->getHeader('X-Forwarded-Proto') === 'https') {
            $scheme = 'https';
        }

        $host = $this->getHeader('Host') ?? 'localhost';

        return $scheme . '://' . $host;
    }

    /**
     * Get a value from the server parameters.
     */
    public function getServerParam(string $key): ?string
    {
        $value = $this->server[$key] ?? null;
        return $value !== null ? (string) $value : null;
    }

    /**
     * Check if this is a POST request.
     */
    public function isPost(): bool
    {
        return $this->method === 'POST';
    }

    /**
     * Check if this is a GET request.
     */
    public function isGet(): bool
    {
        return $this->method === 'GET';
    }

    /**
     * Get the Content-Type header value.
     */
    public function getContentType(): ?string
    {
        return $this->getHeader('Content-Type');
    }

    /**
     * Convert request to an array suitable for logging.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $bodySnippet = $this->body;
        if (strlen($bodySnippet) > 500) {
            $bodySnippet = substr($bodySnippet, 0, 500) . '...[truncated]';
        }

        return [
            'uri'        => $this->uri,
            'path'       => $this->getPath(),
            'method'     => $this->method,
            'headers'    => $this->headers,
            'body'       => $bodySnippet,
            'user_agent' => $this->getUserAgent(),
            'ip'         => $this->ip,
            'post_data'  => $this->postData,
            'query'      => $this->queryParams,
        ];
    }

    /**
     * Extract HTTP headers from $_SERVER array.
     *
     * @param array<string, mixed> $server
     * @return array<string, string>
     */
    private function extractHeaders(array $server): array
    {
        $headers = [];
        foreach ($server as $key => $value) {
            if (str_starts_with($key, 'HTTP_')) {
                $name = str_replace('_', '-', substr($key, 5));
                $name = implode('-', array_map('ucfirst', explode('-', strtolower($name))));
                $headers[$name] = (string) $value;
            }
        }

        // Also capture Content-Type and Content-Length
        if (isset($server['CONTENT_TYPE'])) {
            $headers['Content-Type'] = (string) $server['CONTENT_TYPE'];
        }
        if (isset($server['CONTENT_LENGTH'])) {
            $headers['Content-Length'] = (string) $server['CONTENT_LENGTH'];
        }

        return $headers;
    }
}
