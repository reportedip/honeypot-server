<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Core;

/**
 * HTTP response builder.
 *
 * Provides a fluent interface for constructing and sending HTTP responses.
 */
final class Response
{
    private int $statusCode = 200;

    /** @var array<string, string> */
    private array $headers = [];

    private string $body = '';

    /**
     * Set the HTTP status code.
     */
    public function setStatusCode(int $code): self
    {
        $this->statusCode = $code;
        return $this;
    }

    /**
     * Set an HTTP response header.
     */
    public function setHeader(string $name, string $value): self
    {
        $this->headers[$name] = $value;
        return $this;
    }

    /**
     * Set the response body.
     */
    public function setBody(string $body): self
    {
        $this->body = $body;
        return $this;
    }

    /**
     * Set the Content-Type header.
     */
    public function setContentType(string $type): self
    {
        $this->headers['Content-Type'] = $type;
        return $this;
    }

    /**
     * Set up a redirect response (headers + status only, does not send).
     */
    public function redirect(string $url, int $code = 302): self
    {
        $this->statusCode = $code;
        $this->headers['Location'] = $url;
        $this->body = '';
        return $this;
    }

    /**
     * Set up a JSON response (headers + body only, does not send).
     *
     * @param array<mixed> $data
     */
    public function json(array $data, int $code = 200): self
    {
        $this->statusCode = $code;
        $this->headers['Content-Type'] = 'application/json; charset=utf-8';
        $encoded = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $this->body = $encoded !== false ? $encoded : '{"error":"JSON encoding failed"}';
        return $this;
    }

    /**
     * Render a PHP template file and set the result as body.
     *
     * @param array<string, mixed> $vars Variables available inside the template.
     */
    public function renderTemplate(string $templatePath, array $vars = []): self
    {
        if (!file_exists($templatePath)) {
            $this->statusCode = 500;
            $this->body = '';
            return $this;
        }

        // Render template in isolated scope to avoid variable injection
        $this->body = (string) (static function (string $_path, array $_vars): string {
            extract($_vars, EXTR_SKIP);
            ob_start();
            include $_path;
            return (string) ob_get_clean();
        })($templatePath, $vars);

        return $this;
    }

    /**
     * Send the HTTP response to the client.
     */
    public function send(): void
    {
        if (!headers_sent()) {
            // Remove PHP's default X-Powered-By to avoid leaking the real version
            header_remove('X-Powered-By');

            http_response_code($this->statusCode);

            foreach ($this->headers as $name => $value) {
                header(sprintf('%s: %s', $name, $value));
            }
        }

        echo $this->body;
    }

    /**
     * Get the current status code.
     */
    public function getStatusCode(): int
    {
        return $this->statusCode;
    }

    /**
     * Get all response headers.
     *
     * @return array<string, string>
     */
    public function getHeaders(): array
    {
        return $this->headers;
    }

    /**
     * Get the response body.
     */
    public function getBody(): string
    {
        return $this->body;
    }
}
