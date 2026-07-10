<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Trap;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Core\Response;
use ReportedIp\Honeypot\Profile\CmsProfile;

/**
 * Fake server-info disclosure trap.
 *
 * Serves plausible fake output for the info-leak endpoints scanners love:
 * Apache mod_status (/server-status, /server-info) and Spring Boot Actuator
 * (/actuator, /actuator/env, /actuator/health). Keeps the scanner reading
 * instead of moving on with a bare 404.
 */
final class SystemInfoTrap implements TrapInterface
{
    public function getName(): string
    {
        return 'system_info';
    }

    public function handle(Request $request, Response $response, CmsProfile $profile): Response
    {
        $path = $request->getPath();
        $response->setStatusCode(200);
        $response->setHeader('X-Content-Type-Options', 'nosniff');

        if (preg_match('#/actuator/health$#i', $path)) {
            $response->setContentType('application/vnd.spring-boot.actuator.v3+json');
            $response->setBody('{"status":"UP","groups":["liveness","readiness"]}');
            return $response;
        }

        if (preg_match('#/actuator/env$#i', $path)) {
            $response->setContentType('application/vnd.spring-boot.actuator.v3+json');
            $response->setBody($this->actuatorEnv());
            return $response;
        }

        if (preg_match('#/actuator/?$#i', $path)) {
            $response->setContentType('application/vnd.spring-boot.actuator.v3+json');
            $response->setBody($this->actuatorIndex($request->getBaseUrl()));
            return $response;
        }

        if (preg_match('#/server-info$#i', $path)) {
            $response->setContentType('text/html; charset=UTF-8');
            $response->setBody($this->serverInfo());
            return $response;
        }

        // Default: /server-status
        $response->setContentType('text/html; charset=UTF-8');
        $response->setBody($this->serverStatus());
        return $response;
    }

    private function serverStatus(): string
    {
        $now = gmdate('D, d M Y H:i:s') . ' UTC';

        return <<<HTML
        <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
        <html><head><title>Apache Status</title></head><body>
        <h1>Apache Server Status for localhost (via 127.0.0.1)</h1>
        <dl>
        <dt>Server Version: Apache/2.4.58 (Ubuntu)</dt>
        <dt>Server MPM: event</dt>
        <dt>Current Time: {$now}</dt>
        <dt>Restart Time: {$now}</dt>
        <dt>Total accesses: 184217 - Total Traffic: 3.1 GB</dt>
        <dt>2 requests currently being processed, 8 idle workers</dt>
        </dl>
        <pre>__W__............................................................</pre>
        <hr>
        <address>Apache/2.4.58 (Ubuntu) Server at localhost Port 80</address>
        </body></html>
        HTML;
    }

    private function serverInfo(): string
    {
        return <<<HTML
        <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
        <html><head><title>Apache Server Information</title></head><body>
        <h1>Apache Server Information</h1>
        <dl><dt><strong>Server Version: Apache/2.4.58 (Ubuntu)</strong></dt>
        <dt>Server Built: 2024-04-04</dt></dl>
        <hr>
        <h2>Loaded Modules</h2>
        <p>core.c, mod_so.c, http_core.c, mod_php.c, mod_ssl.c, mod_rewrite.c, mod_headers.c</p>
        <hr>
        <address>Apache/2.4.58 (Ubuntu) Server at localhost Port 80</address>
        </body></html>
        HTML;
    }

    private function actuatorIndex(string $base): string
    {
        $b = rtrim($base, '/') . '/actuator';
        return '{"_links":{"self":{"href":"' . $b . '","templated":false},'
            . '"health":{"href":"' . $b . '/health","templated":false},'
            . '"env":{"href":"' . $b . '/env","templated":false},'
            . '"info":{"href":"' . $b . '/info","templated":false}}}';
    }

    private function actuatorEnv(): string
    {
        return '{"activeProfiles":["production"],"propertySources":['
            . '{"name":"systemProperties","properties":{"java.version":{"value":"17.0.10"},'
            . '"user.timezone":{"value":"UTC"}}},'
            . '{"name":"applicationConfig","properties":{'
            . '"spring.datasource.url":{"value":"jdbc:mysql://localhost:3306/app"},'
            . '"spring.datasource.username":{"value":"app_prod"},'
            . '"server.port":{"value":"8080"}}}]}';
    }
}
