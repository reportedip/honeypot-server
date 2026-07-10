<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Trap;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Core\Response;
use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Persistence\PayloadCapture;
use ReportedIp\Honeypot\Profile\CmsProfile;

/**
 * Fake webshell trap.
 *
 * When an attacker requests a known webshell filename (shell.php, wso.php, an
 * uploads/*.php file, ...) they are checking whether a dropped shell is live.
 * Serving a minimal password-gated shell prompt keeps them interacting, and
 * any command or password they POST is captured for threat intel. No command
 * is ever executed — the "shell" only ever answers "wrong password".
 */
final class WebshellTrap implements TrapInterface, DatabaseAwareInterface
{
    private ?Database $db = null;

    public function getName(): string
    {
        return 'webshell';
    }

    public function setDatabase(Database $db): void
    {
        $this->db = $db;
    }

    public function handle(Request $request, Response $response, CmsProfile $profile): Response
    {
        // Match the profile's Server header to avoid a fingerprintable mismatch.
        $serverHeader = $profile->getDefaultHeaders()['Server'] ?? null;
        if ($serverHeader !== null) {
            $response->setHeader('Server', $serverHeader);
        }
        $response->setContentType('text/html; charset=UTF-8');
        $response->setStatusCode(200);
        $response->setHeader('X-Content-Type-Options', 'nosniff');

        if ($request->isPost() || $request->getPostData() !== []) {
            $this->capture($request);
            usleep(random_int(100000, 300000));
        }

        // A bare, generic shell-auth prompt. Convincing enough that automated
        // shell-checkers register a "live" endpoint, but functionally inert.
        $response->setBody(
            "<!DOCTYPE html><html><head><title>.</title></head><body>"
            . "<form method=\"post\">"
            . "<input type=\"password\" name=\"pass\" autofocus>"
            . "<input type=\"submit\" value=\"&gt;\">"
            . "</form></body></html>"
        );

        return $response;
    }

    /**
     * Capture the submitted command/password payload.
     */
    private function capture(Request $request): void
    {
        if ($this->db === null) {
            return;
        }

        $parts = [];
        $post = $request->getPostData();
        if ($post !== []) {
            $encoded = json_encode($post, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if ($encoded !== false) {
                $parts[] = $encoded;
            }
        }
        $body = $request->getBody();
        if ($body !== '') {
            $parts[] = $body;
        }

        (new PayloadCapture($this->db))->store(
            $request,
            'webshell_post',
            implode("\n", $parts),
            basename($request->getPath()),
            $request->getContentType() ?? ''
        );
    }
}
