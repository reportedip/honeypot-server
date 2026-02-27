<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Admin;

use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Core\Request;

/**
 * Admin panel authentication handler.
 *
 * Manages session-based authentication for the honeypot admin panel
 * using bcrypt password verification against the configured hash.
 */
final class AdminAuth
{
    private const SESSION_KEY = 'hp_admin_auth';
    private const SESSION_LIFETIME = 3600; // 1 hour
    private const COOKIE_NAME = 'hp_session';
    private const MAX_LOGIN_ATTEMPTS = 5;
    private const LOCKOUT_WINDOW = 900; // 15 minutes

    private Config $config;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /**
     * Check if the current request is authenticated.
     */
    public function isAuthenticated(Request $request): bool
    {
        $this->ensureSession();

        if (!isset($_SESSION[self::SESSION_KEY])) {
            return false;
        }

        $sessionData = $_SESSION[self::SESSION_KEY];

        // Check session expiry
        if (!isset($sessionData['expires']) || $sessionData['expires'] < time()) {
            $this->logout();
            return false;
        }

        // Check IP binding (prevent session hijacking)
        if (isset($sessionData['ip']) && $sessionData['ip'] !== $request->getIp()) {
            $this->logout();
            return false;
        }

        return true;
    }

    /**
     * Check if the given IP is currently locked out due to too many failed login attempts.
     *
     * Returns the number of seconds remaining if locked out, or 0 if not locked.
     */
    public function getLockoutRemaining(string $ip): int
    {
        $attempts = $this->getLoginAttempts($ip);
        if ($attempts >= self::MAX_LOGIN_ATTEMPTS) {
            $lastAttempt = $this->getLastAttemptTime($ip);
            $unlockTime = $lastAttempt + self::LOCKOUT_WINDOW;
            if (time() < $unlockTime) {
                return $unlockTime - time();
            }
            // Window expired, clear attempts
            $this->clearLoginAttempts($ip);
        }
        return 0;
    }

    /**
     * Attempt to log in with the given password.
     *
     * Returns true if authentication succeeds.
     */
    public function login(string $password, Request $request): bool
    {
        $hash = $this->config->get('admin_password_hash', '');

        if (empty($hash)) {
            return false;
        }

        $ip = $request->getIp();

        // Check brute-force lockout
        if ($this->getLockoutRemaining($ip) > 0) {
            return false;
        }

        // Constant-time comparison via bcrypt
        if (!password_verify($password, $hash)) {
            $this->recordFailedAttempt($ip);
            // Add a small delay to mitigate brute force
            usleep(random_int(200000, 500000));
            return false;
        }

        // Successful login - clear failed attempts
        $this->clearLoginAttempts($ip);

        $this->ensureSession();

        // Regenerate session ID on login to prevent fixation
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_regenerate_id(true);
        }

        $_SESSION[self::SESSION_KEY] = [
            'authenticated' => true,
            'ip'            => $request->getIp(),
            'expires'       => time() + self::SESSION_LIFETIME,
            'created'       => time(),
        ];

        return true;
    }

    /**
     * Destroy the current session and log out.
     */
    public function logout(): void
    {
        $this->ensureSession();

        // Clear all session data
        $_SESSION = [];

        // Delete session cookie
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                time() - 42000,
                $params['path'],
                $params['domain'],
                $params['secure'],
                $params['httponly']
            );
        }

        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
    }

    /**
     * Extend the session expiry for active users.
     */
    public function touch(): void
    {
        if (isset($_SESSION[self::SESSION_KEY])) {
            $_SESSION[self::SESSION_KEY]['expires'] = time() + self::SESSION_LIFETIME;
        }
    }

    /**
     * Check if admin authentication is configured.
     */
    public function isConfigured(): bool
    {
        $hash = $this->config->get('admin_password_hash', '');
        return !empty($hash);
    }

    /**
     * Start or resume a session.
     */
    private function ensureSession(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            // Secure session settings
            $adminPath = $this->config->get('admin_path', '/_hp_admin');

            session_set_cookie_params([
                'lifetime' => self::SESSION_LIFETIME,
                'path'     => $adminPath,
                'secure'   => $this->isHttps(),
                'httponly'  => true,
                'samesite'  => 'Strict',
            ]);

            session_name(self::COOKIE_NAME);
            session_start();
        }
    }

    /**
     * Detect if the current request is over HTTPS.
     * Only trusts X-Forwarded-Proto header if the request comes from a trusted proxy.
     */
    private function isHttps(): bool
    {
        if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
            return true;
        }
        if (isset($_SERVER['SERVER_PORT']) && (int) $_SERVER['SERVER_PORT'] === 443) {
            return true;
        }

        // Only trust forwarded headers from configured trusted proxies
        if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
            $trustedProxies = (array) $this->config->get('trusted_proxies', []);
            if (!empty($trustedProxies)) {
                $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '';
                if (in_array($remoteAddr, $trustedProxies, true)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Get the path to the login attempts file.
     */
    private function getAttemptsFile(): string
    {
        $dataDir = dirname(__DIR__, 2) . '/data';
        if (!is_dir($dataDir)) {
            @mkdir($dataDir, 0750, true);
        }
        return $dataDir . '/login_attempts.json';
    }

    /**
     * Load all login attempt data.
     *
     * @return array<string, array{count: int, last: int}>
     */
    private function loadAttempts(): array
    {
        $file = $this->getAttemptsFile();
        if (!file_exists($file)) {
            return [];
        }

        $data = @json_decode((string) file_get_contents($file), true);
        if (!is_array($data)) {
            return [];
        }

        // Prune expired entries
        $now = time();
        $pruned = false;
        foreach ($data as $ip => $info) {
            if (!isset($info['last']) || ($info['last'] + self::LOCKOUT_WINDOW) < $now) {
                unset($data[$ip]);
                $pruned = true;
            }
        }

        if ($pruned) {
            $this->saveAttempts($data);
        }

        return $data;
    }

    /**
     * Save login attempt data.
     *
     * @param array<string, array{count: int, last: int}> $data
     */
    private function saveAttempts(array $data): void
    {
        $file = $this->getAttemptsFile();
        @file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX);
    }

    /**
     * Get the number of failed login attempts for an IP.
     */
    private function getLoginAttempts(string $ip): int
    {
        $data = $this->loadAttempts();
        return $data[$ip]['count'] ?? 0;
    }

    /**
     * Get the timestamp of the last failed attempt for an IP.
     */
    private function getLastAttemptTime(string $ip): int
    {
        $data = $this->loadAttempts();
        return $data[$ip]['last'] ?? 0;
    }

    /**
     * Record a failed login attempt for an IP.
     */
    private function recordFailedAttempt(string $ip): void
    {
        $data = $this->loadAttempts();
        if (!isset($data[$ip])) {
            $data[$ip] = ['count' => 0, 'last' => 0];
        }
        $data[$ip]['count']++;
        $data[$ip]['last'] = time();
        $this->saveAttempts($data);
    }

    /**
     * Clear failed login attempts for an IP.
     */
    private function clearLoginAttempts(string $ip): void
    {
        $data = $this->loadAttempts();
        unset($data[$ip]);
        $this->saveAttempts($data);
    }
}
