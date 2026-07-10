<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Trap;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Core\Response;
use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Persistence\PayloadCapture;
use ReportedIp\Honeypot\Profile\CmsProfile;

/**
 * Fake database-admin tool trap (phpMyAdmin / Adminer).
 *
 * These panels are heavily scanned but not part of any CMS the honeypot
 * emulates, so a convincing login screen keeps the scanner engaged and its
 * submitted credentials are captured for intel. Login always "fails".
 */
final class DbAdminTrap implements TrapInterface, DatabaseAwareInterface
{
    private ?Database $db = null;

    public function getName(): string
    {
        return 'db_admin';
    }

    public function setDatabase(Database $db): void
    {
        $this->db = $db;
    }

    public function handle(Request $request, Response $response, CmsProfile $profile): Response
    {
        // Match the profile's Server header so this panel is not fingerprintable
        // by a header mismatch, but skip the WordPress-specific headers (Link,
        // X-Pingback) that would themselves be out of place on a DB-admin page.
        $serverHeader = $profile->getDefaultHeaders()['Server'] ?? null;
        if ($serverHeader !== null) {
            $response->setHeader('Server', $serverHeader);
        }
        $response->setHeader('X-Content-Type-Options', 'nosniff');
        $response->setContentType('text/html; charset=UTF-8');
        $response->setStatusCode(200);

        $isAdminer = (bool) preg_match('#adminer#i', $request->getPath());

        if ($request->isPost()) {
            usleep(random_int(150000, 450000));
            $this->captureCredentials($request, $isAdminer);
            $response->setBody($isAdminer
                ? $this->adminerPage('Invalid credentials.')
                : $this->phpMyAdminPage('#1045 - Access denied for user (using password: YES)'));
            return $response;
        }

        $response->setBody($isAdminer ? $this->adminerPage('') : $this->phpMyAdminPage(''));
        return $response;
    }

    /**
     * Store any submitted DB-admin credentials for later analysis.
     */
    private function captureCredentials(Request $request, bool $isAdminer): void
    {
        if ($this->db === null) {
            return;
        }

        $post = $request->getPostData();
        $encoded = json_encode($post, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        (new PayloadCapture($this->db))->store(
            $request,
            $isAdminer ? 'adminer_login' : 'phpmyadmin_login',
            $encoded !== false ? $encoded : '',
            '',
            'application/x-www-form-urlencoded'
        );
    }

    private function phpMyAdminPage(string $error): string
    {
        $errorHtml = $error !== ''
            ? '<div class="error">' . htmlspecialchars($error, ENT_QUOTES, 'UTF-8') . '</div>'
            : '';

        return <<<HTML
        <!DOCTYPE html>
        <html lang="en" dir="ltr">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="robots" content="noindex,nofollow">
        <title>phpMyAdmin</title>
        <style>
        body{font-family:sans-serif;background:#f5f5f5;color:#333;margin:0}
        #page{width:400px;margin:80px auto;background:#fff;border:1px solid #ccc;padding:0}
        .header{background:#6c78af;color:#fff;padding:14px 20px;font-size:18px}
        form{padding:24px 20px}
        label{display:block;margin:10px 0 4px;font-size:13px}
        input[type=text],input[type=password]{width:100%;padding:7px;border:1px solid #aaa;box-sizing:border-box}
        .error{background:#f2dede;color:#a94442;border:1px solid #ebccd1;padding:10px;margin:16px 20px 0;font-size:13px}
        .btn{margin-top:18px;background:#6c78af;color:#fff;border:0;padding:9px 22px;cursor:pointer}
        .footer{color:#999;font-size:11px;text-align:center;padding:12px}
        </style>
        </head>
        <body>
        <div id="page">
        <div class="header">phpMyAdmin</div>
        {$errorHtml}
        <form method="post" action="index.php">
        <label for="input_username">Username:</label>
        <input type="text" name="pma_username" id="input_username" value="" autocomplete="username">
        <label for="input_password">Password:</label>
        <input type="password" name="pma_password" id="input_password" value="" autocomplete="current-password">
        <label for="input_servername">Server Choice:</label>
        <input type="text" name="pma_servername" id="input_servername" value="localhost">
        <input type="submit" class="btn" value="Go">
        </form>
        <div class="footer">phpMyAdmin 5.2.1</div>
        </div>
        </body>
        </html>
        HTML;
    }

    private function adminerPage(string $error): string
    {
        $errorHtml = $error !== ''
            ? '<div class="error">' . htmlspecialchars($error, ENT_QUOTES, 'UTF-8') . '</div>'
            : '';

        return <<<HTML
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="robots" content="noindex">
        <title>Login - Adminer</title>
        <style>
        body{font-family:sans-serif;margin:1em;color:#000}
        h1{font-size:150%;margin:.2em 0}
        .error{background:#fdd;padding:.5em;margin:.5em 0;border:1px solid #c00}
        table{border-collapse:collapse}
        th{text-align:right;padding:.3em .5em;font-weight:normal}
        input{padding:.2em;border:1px solid #999}
        .h1{background:#eee;padding:.3em .5em}
        </style>
        </head>
        <body>
        <div class="h1">Adminer 4.8.1</div>
        <h1>Login</h1>
        {$errorHtml}
        <form action="" method="post">
        <table>
        <tr><th>System<td><select name="auth[driver]"><option value="server">MySQL</option></select>
        <tr><th>Server<td><input name="auth[server]" value="localhost">
        <tr><th>Username<td><input name="auth[username]" value="" autocomplete="username">
        <tr><th>Password<td><input type="password" name="auth[password]" autocomplete="current-password">
        <tr><th>Database<td><input name="auth[db]" value="">
        </table>
        <p><input type="submit" value="Login">
        </form>
        </body>
        </html>
        HTML;
    }
}
