<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Trap;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Core\Response;
use ReportedIp\Honeypot\Detection\Honeytoken;
use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Profile\CmsProfile;

/**
 * Source-code and secret disclosure trap.
 *
 * Serves convincing fake responses for the most-scanned disclosure paths:
 * .env environment files and exposed .git / .svn repository metadata. The
 * leaked credentials are unique per source IP (honeytokens); if the attacker
 * later replays one of them it is caught by {@see Honeytoken::detectReuse()}
 * as a confirmed-malicious event.
 */
final class SourceLeakTrap implements TrapInterface, DatabaseAwareInterface
{
    private ?Database $db = null;

    public function getName(): string
    {
        return 'source_leak';
    }

    public function setDatabase(Database $db): void
    {
        $this->db = $db;
    }

    public function handle(Request $request, Response $response, CmsProfile $profile): Response
    {
        foreach ($profile->getDefaultHeaders() as $name => $value) {
            $response->setHeader($name, $value);
        }

        $path = $request->getPath();
        $ip = $request->getIp();

        // .env and its common variants
        if (preg_match('#(?:^|/)\.env(\.[\w.-]+)?$#i', $path)) {
            $response->setStatusCode(200);
            $response->setContentType('text/plain; charset=UTF-8');
            $response->setBody($this->fakeEnvFile($ip, $path));
            return $response;
        }

        // .git/config — INI with a remote whose URL carries a honeytoken token
        if (preg_match('#/\.git/config$#i', $path)) {
            $response->setStatusCode(200);
            $response->setContentType('text/plain; charset=UTF-8');
            $response->setBody($this->fakeGitConfig($ip, $path));
            return $response;
        }

        // .git/HEAD
        if (preg_match('#/\.git/HEAD$#i', $path)) {
            $response->setStatusCode(200);
            $response->setContentType('text/plain; charset=UTF-8');
            $response->setBody("ref: refs/heads/main\n");
            return $response;
        }

        // .git/logs/HEAD — reflog with an author e-mail
        if (preg_match('#/\.git/logs/HEAD$#i', $path)) {
            $response->setStatusCode(200);
            $response->setContentType('text/plain; charset=UTF-8');
            $response->setBody($this->fakeGitReflog());
            return $response;
        }

        // .git/index — binary-ish blob so DVCS-ripper tools keep going
        if (preg_match('#/\.git/index$#i', $path)) {
            $response->setStatusCode(200);
            $response->setContentType('application/octet-stream');
            $response->setBody($this->fakeGitIndex());
            return $response;
        }

        // .svn/entries and wc.db
        if (preg_match('#/\.svn/(entries|wc\.db)$#i', $path)) {
            $response->setStatusCode(200);
            $response->setContentType('text/plain; charset=UTF-8');
            $response->setBody("12\n\ndir\n0\nhttps://svn.example.com/repo/trunk\n");
            return $response;
        }

        $notFound = new NotFoundTrap();
        return $notFound->handle($request, $response, $profile);
    }

    /**
     * Build a fake .env populated with per-IP honeytoken credentials.
     */
    private function fakeEnvFile(string $ip, string $path): string
    {
        $dbPass    = $this->token('db_password', $ip, $path);
        $appKey    = 'base64:' . $this->token('app_key', $ip, $path);
        $awsKey    = 'AKIA' . strtoupper(substr($this->token('aws_key', $ip, $path), 3, 16));
        $awsSecret = $this->token('aws_secret', $ip, $path);
        $mailPass  = $this->token('mail_password', $ip, $path);
        $jwtSecret = $this->token('jwt_secret', $ip, $path);

        return <<<ENV
        APP_NAME=Laravel
        APP_ENV=production
        APP_KEY={$appKey}
        APP_DEBUG=false
        APP_URL=https://example.com

        LOG_CHANNEL=stack

        DB_CONNECTION=mysql
        DB_HOST=127.0.0.1
        DB_PORT=3306
        DB_DATABASE=app_production
        DB_USERNAME=app_prod
        DB_PASSWORD={$dbPass}

        BROADCAST_DRIVER=log
        CACHE_DRIVER=redis
        QUEUE_CONNECTION=redis
        SESSION_DRIVER=redis
        SESSION_LIFETIME=120

        REDIS_HOST=127.0.0.1
        REDIS_PASSWORD=null
        REDIS_PORT=6379

        MAIL_MAILER=smtp
        MAIL_HOST=smtp.mailgun.org
        MAIL_PORT=587
        MAIL_USERNAME=postmaster@example.com
        MAIL_PASSWORD={$mailPass}
        MAIL_ENCRYPTION=tls

        AWS_ACCESS_KEY_ID={$awsKey}
        AWS_SECRET_ACCESS_KEY={$awsSecret}
        AWS_DEFAULT_REGION=eu-central-1
        AWS_BUCKET=app-prod-uploads

        JWT_SECRET={$jwtSecret}

        ENV;
    }

    /**
     * Build a fake .git/config whose remote URL embeds a honeytoken.
     */
    private function fakeGitConfig(string $ip, string $path): string
    {
        $token = $this->token('git_token', $ip, $path);

        return <<<INI
        [core]
        \trepositoryformatversion = 0
        \tfilemode = true
        \tbare = false
        \tlogallrefupdates = true
        [remote "origin"]
        \turl = https://ci-deploy:{$token}@git.example.com/app/production.git
        \tfetch = +refs/heads/*:refs/remotes/origin/*
        [branch "main"]
        \tremote = origin
        \tmerge = refs/heads/main

        INI;
    }

    private function fakeGitReflog(): string
    {
        $zero = str_repeat('0', 40);
        $a = sha1('honeypot-commit-a');
        $b = sha1('honeypot-commit-b');
        $ts = '1700000000 +0000';

        return "{$zero} {$a} Deploy Bot <deploy@example.com> {$ts}\tclone: from git.example.com\n"
            . "{$a} {$b} Deploy Bot <deploy@example.com> {$ts}\tcommit: production hotfix\n";
    }

    private function fakeGitIndex(): string
    {
        // "DIRC" signature + version 2 + a small fake entry count, then padding.
        return "DIRC\x00\x00\x00\x02\x00\x00\x00\x03" . str_repeat("\x00", 60);
    }

    /**
     * Issue (or reuse) a honeytoken for this IP, falling back to a random value
     * if no database is wired up.
     */
    private function token(string $type, string $ip, string $path): string
    {
        if ($this->db !== null) {
            return (new Honeytoken($this->db))->issue($type, $ip, $path);
        }
        return Honeytoken::MARKER . bin2hex(random_bytes(8));
    }
}
