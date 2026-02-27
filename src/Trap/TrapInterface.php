<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Trap;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Core\Response;
use ReportedIp\Honeypot\Profile\CmsProfile;

/**
 * Interface for all honeypot traps.
 *
 * Each trap handles a specific category of request (login, admin, API, etc.)
 * and returns a convincing CMS-like response.
 */
interface TrapInterface
{
    /**
     * Handle the incoming request and populate the response.
     */
    public function handle(Request $request, Response $response, CmsProfile $profile): Response;

    /**
     * Get the trap identifier name.
     */
    public function getName(): string;
}
