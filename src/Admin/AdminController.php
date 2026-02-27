<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Admin;

use ReportedIp\Honeypot\Content\ContentGenerator;
use ReportedIp\Honeypot\Content\ContentRepository;
use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Core\Response;
use ReportedIp\Honeypot\Detection\CategoryRegistry;
use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Persistence\Logger;
use ReportedIp\Honeypot\Persistence\VisitorLogger;
use ReportedIp\Honeypot\Persistence\Whitelist;

/**
 * Admin panel controller.
 *
 * Routes admin panel requests to the appropriate handler (login, dashboard,
 * logs, whitelist management) and renders admin templates.
 */
final class AdminController
{
    private Config $config;
    private Database $db;
    private Logger $logger;
    private Whitelist $whitelist;
    private AdminAuth $auth;
    private string $adminPath;
    private string $templateDir;

    public function __construct(Config $config, Database $db, Logger $logger, Whitelist $whitelist)
    {
        $this->config = $config;
        $this->db = $db;
        $this->logger = $logger;
        $this->whitelist = $whitelist;
        $this->auth = new AdminAuth($config);
        $this->adminPath = $config->get('admin_path', '/_hp_admin');
        $this->templateDir = __DIR__ . '/../../templates/admin';
    }

    /**
     * Handle an admin panel request.
     */
    public function handle(Request $request): void
    {
        // Emit security headers for all admin responses
        $this->sendSecurityHeaders();

        // Determine the admin sub-path
        $fullPath = $request->getPath();
        $subPath = substr($fullPath, strlen($this->adminPath));
        $subPath = $subPath === '' || $subPath === false ? '/' : $subPath;

        // Check authentication (login page is exempt)
        if ($subPath !== '/login' && $subPath !== '/login/') {
            if (!$this->auth->isAuthenticated($request)) {
                $response = new Response();
                $response->redirect($this->adminPath . '/login');
                $response->send();
                return;
            }
            $this->auth->touch();
        }

        // Route to the appropriate handler
        switch (true) {
            case $subPath === '/login' || $subPath === '/login/':
                $this->handleLogin($request);
                break;

            case $subPath === '/logout' || $subPath === '/logout/':
                $this->handleLogout($request);
                break;

            case $subPath === '/logs' || $subPath === '/logs/' || str_starts_with($subPath, '/logs/'):
                $this->handleLogs($request, $subPath);
                break;

            case $subPath === '/whitelist' || $subPath === '/whitelist/':
                $this->handleWhitelist($request);
                break;

            case str_starts_with($subPath, '/content'):
                $this->handleContent($request, $subPath);
                break;

            case str_starts_with($subPath, '/visitors'):
                $this->handleVisitors($request, $subPath);
                break;

            case str_starts_with($subPath, '/updates'):
                $this->handleUpdates($request, $subPath);
                break;

            case $subPath === '/api/stats':
                $this->handleApiStats();
                break;

            default:
                $this->handleDashboard($request);
                break;
        }
    }

    /**
     * Handle the login page and login form submission.
     */
    private function handleLogin(Request $request): void
    {
        $response = new Response();
        $error = '';

        // Already authenticated? Redirect to dashboard
        if ($this->auth->isAuthenticated($request)) {
            $response->redirect($this->adminPath . '/');
            $response->send();
            return;
        }

        // Not configured?
        if (!$this->auth->isConfigured()) {
            $response->setContentType('text/html; charset=utf-8');
            $response->setBody('<html><body><h1>Admin Not Configured</h1>'
                . '<p>Run <code>php install.php</code> to set an admin password.</p></body></html>');
            $response->send();
            return;
        }

        // Check brute-force lockout
        $lockoutRemaining = $this->auth->getLockoutRemaining($request->getIp());
        if ($lockoutRemaining > 0) {
            $minutes = (int) ceil($lockoutRemaining / 60);
            $error = sprintf('Too many login attempts. Try again in %d minute%s.', $minutes, $minutes !== 1 ? 's' : '');
        } elseif ($request->isPost()) {
            // Process login form
            $postData = $request->getPostData();
            $password = (string) ($postData['password'] ?? '');

            // CSRF check
            $token = (string) ($postData['csrf_token'] ?? '');
            if (!$this->verifyCsrfToken($token)) {
                $error = 'Invalid form submission. Please try again.';
            } elseif ($this->auth->login($password, $request)) {
                $response->redirect($this->adminPath . '/');
                $response->send();
                return;
            } else {
                // Re-check lockout after failed attempt
                $lockoutRemaining = $this->auth->getLockoutRemaining($request->getIp());
                if ($lockoutRemaining > 0) {
                    $minutes = (int) ceil($lockoutRemaining / 60);
                    $error = sprintf('Too many login attempts. Try again in %d minute%s.', $minutes, $minutes !== 1 ? 's' : '');
                } else {
                    $error = 'Invalid password.';
                }
            }
        }

        $csrfToken = $this->generateCsrfToken();

        $response->setContentType('text/html; charset=utf-8');
        $response->renderTemplate($this->templateDir . '/login.php', [
            'error'      => $error,
            'csrf_token' => $csrfToken,
            'admin_path' => $this->adminPath,
        ]);
        $response->send();
    }

    /**
     * Handle logout (requires POST with CSRF token).
     */
    private function handleLogout(Request $request): void
    {
        $response = new Response();

        if ($request->isPost()) {
            $postData = $request->getPostData();
            $token = (string) ($postData['csrf_token'] ?? '');

            if ($this->verifyCsrfToken($token)) {
                $this->auth->logout();
                $response->redirect($this->adminPath . '/login');
                $response->send();
                return;
            }
        }

        // GET or invalid CSRF — redirect to dashboard
        $response->redirect($this->adminPath . '/');
        $response->send();
    }

    /**
     * Handle the dashboard page.
     */
    private function handleDashboard(Request $request): void
    {
        $dashboard = new Dashboard($this->db, $this->logger, $this->whitelist, $this->config);
        $data = $dashboard->getData();

        $response = new Response();
        $response->setContentType('text/html; charset=utf-8');
        $response->renderTemplate($this->templateDir . '/dashboard.php', array_merge($data, [
            'admin_path'       => $this->adminPath,
            'csrf_token'       => $this->generateCsrfToken(),
            'categoryRegistry' => CategoryRegistry::class,
        ]));
        $response->send();
    }

    /**
     * Handle the log viewer page.
     */
    private function handleLogs(Request $request, string $subPath): void
    {
        $viewer = new LogViewer($this->db, $this->logger);

        // Check for detail view: /logs/view/123
        if (preg_match('#^/logs/view/(\d+)#', $subPath, $matches)) {
            $entry = $viewer->getEntry((int) $matches[1]);
            if ($entry === null) {
                $response = new Response();
                $response->setStatusCode(404);
                $response->setContentType('text/html; charset=utf-8');
                $response->setBody('<html><body><h1>Log Entry Not Found</h1></body></html>');
                $response->send();
                return;
            }

            $response = new Response();
            $response->setContentType('text/html; charset=utf-8');
            $response->renderTemplate($this->templateDir . '/log_detail.php', [
                'entry'            => $entry,
                'admin_path'       => $this->adminPath,
                'csrf_token'       => $this->generateCsrfToken(),
                'categoryRegistry' => CategoryRegistry::class,
            ]);
            $response->send();
            return;
        }

        // Paginated list
        $page = (int) ($request->getQueryParam('page') ?? '1');
        $filters = [
            'ip'       => $request->getQueryParam('ip') ?? '',
            'category' => $request->getQueryParam('category') ?? '',
            'method'   => $request->getQueryParam('method') ?? '',
            'sent'     => $request->getQueryParam('sent') ?? '',
            'search'   => $request->getQueryParam('search') ?? '',
        ];

        $result = $viewer->getPage($page, $filters);

        $response = new Response();
        $response->setContentType('text/html; charset=utf-8');
        $response->renderTemplate($this->templateDir . '/logs.php', array_merge($result, [
            'filters'          => $filters,
            'categories'       => $viewer->getUsedCategories(),
            'methods'          => $viewer->getUsedMethods(),
            'admin_path'       => $this->adminPath,
            'csrf_token'       => $this->generateCsrfToken(),
            'categoryRegistry' => CategoryRegistry::class,
        ]));
        $response->send();
    }

    /**
     * Handle whitelist management actions.
     */
    private function handleWhitelist(Request $request): void
    {
        $message = '';
        $messageType = '';

        if ($request->isPost()) {
            $postData = $request->getPostData();
            $token = (string) ($postData['csrf_token'] ?? '');

            if ($this->verifyCsrfToken($token)) {
                $action = (string) ($postData['action'] ?? '');

                switch ($action) {
                    case 'add':
                        $ip = trim((string) ($postData['ip'] ?? ''));
                        $desc = trim((string) ($postData['description'] ?? ''));
                        $validCidr = false;
                        if (str_contains($ip, '/')) {
                            [$subnet, $bits] = explode('/', $ip, 2);
                            $isIpv6 = str_contains($subnet, ':');
                            $maxBits = $isIpv6 ? 128 : 32;
                            $validCidr = filter_var($subnet, FILTER_VALIDATE_IP) !== false
                                && is_numeric($bits)
                                && (int) $bits >= 0
                                && (int) $bits <= $maxBits;
                        }
                        if ($ip !== '' && (filter_var($ip, FILTER_VALIDATE_IP) !== false || $validCidr)) {
                            $this->whitelist->add($ip, $desc);
                            $message = 'IP added to whitelist: ' . htmlspecialchars($ip, ENT_QUOTES, 'UTF-8');
                            $messageType = 'success';
                        } else {
                            $message = 'Invalid IP address or CIDR range.';
                            $messageType = 'error';
                        }
                        break;

                    case 'remove':
                        $ip = trim((string) ($postData['ip'] ?? ''));
                        if ($ip !== '') {
                            $this->whitelist->remove($ip);
                            $message = 'IP removed from whitelist: ' . htmlspecialchars($ip, ENT_QUOTES, 'UTF-8');
                            $messageType = 'success';
                        }
                        break;
                }
            } else {
                $message = 'Invalid form submission.';
                $messageType = 'error';
            }
        }

        $response = new Response();
        $response->setContentType('text/html; charset=utf-8');
        $response->renderTemplate($this->templateDir . '/dashboard.php', array_merge(
            (new Dashboard($this->db, $this->logger, $this->whitelist, $this->config))->getData(),
            [
                'admin_path'       => $this->adminPath,
                'csrf_token'       => $this->generateCsrfToken(),
                'message'          => $message,
                'message_type'     => $messageType,
                'active_tab'       => 'whitelist',
                'categoryRegistry' => CategoryRegistry::class,
            ]
        ));
        $response->send();
    }

    /**
     * JSON API endpoint for live stats updates.
     */
    private function handleApiStats(): void
    {
        $dashboard = new Dashboard($this->db, $this->logger, $this->whitelist, $this->config);
        $stats = $this->logger->getStats();
        $chart = $dashboard->getChartData();

        $response = new Response();
        $response->json([
            'stats'      => $stats,
            'chart_data' => $chart,
        ]);
        $response->send();
    }

    /**
     * Handle content management routes.
     */
    private function handleContent(Request $request, string $subPath): void
    {
        $repo = new ContentRepository($this->db);
        $cmsProfile = $this->config->get('cms_profile', 'wordpress');
        $response = new Response();

        // POST /content/api/generate-one — AJAX: generate a single post
        if ($subPath === '/content/api/generate-one' && $request->isPost()) {
            $postData = $request->getPostData();
            $token = (string) ($postData['csrf_token'] ?? '');

            if (!$this->verifyCsrfToken($token)) {
                $response->json(['error' => 'Invalid CSRF token. Please reload the page.'], 403);
                $response->send();
                return;
            }

            // Re-issue token so the next request also works
            $newToken = $this->generateCsrfToken();

            $generator = new ContentGenerator($this->config);
            if (!$generator->isConfigured()) {
                $response->json(['error' => 'OpenAI API key is not configured.', 'csrf_token' => $newToken], 400);
                $response->send();
                return;
            }

            $topic = trim((string) ($postData['topic'] ?? ''));
            $style = trim((string) ($postData['style'] ?? ''));
            $language = in_array(($postData['language'] ?? ''), ['de', 'en'], true)
                ? (string) $postData['language']
                : $this->config->get('content_language', 'en');

            try {
                $post = $generator->generate($cmsProfile, $topic, $style, $language);
                // Assign a realistic published_date spread over 6-12 months
                $daysAgo = random_int(30, 365);
                $post['published_date'] = date('Y-m-d H:i:s', strtotime("-{$daysAgo} days"));

                // Append to session preview array
                if (session_status() === PHP_SESSION_NONE) {
                    session_start();
                }
                if (!isset($_SESSION['generated_preview']) || !is_array($_SESSION['generated_preview'])) {
                    $_SESSION['generated_preview'] = [];
                }
                $_SESSION['generated_preview'][] = $post;
                $index = count($_SESSION['generated_preview']) - 1;

                $response->json([
                    'success'    => true,
                    'post'       => $post,
                    'index'      => $index,
                    'csrf_token' => $newToken,
                ]);
            } catch (\Throwable $e) {
                error_log('[honeypot] content generation error: ' . $e->getMessage());
                $response->json([
                    'error'      => 'Content generation failed. Check server logs for details.',
                    'csrf_token' => $newToken,
                ], 500);
            }
            $response->send();
            return;
        }

        // POST /content/api/reset-preview — AJAX: clear session preview before new generation
        if ($subPath === '/content/api/reset-preview' && $request->isPost()) {
            $postData = $request->getPostData();
            $token = (string) ($postData['csrf_token'] ?? '');

            if (!$this->verifyCsrfToken($token)) {
                $response->json(['error' => 'Invalid CSRF token.'], 403);
                $response->send();
                return;
            }

            if (session_status() === PHP_SESSION_NONE) {
                session_start();
            }
            $_SESSION['generated_preview'] = [];
            $response->json(['success' => true, 'csrf_token' => $this->generateCsrfToken()]);
            $response->send();
            return;
        }

        // POST /content/save — save previewed content
        if ($subPath === '/content/save' && $request->isPost()) {
            $postData = $request->getPostData();
            $token = (string) ($postData['csrf_token'] ?? '');

            if ($this->verifyCsrfToken($token)) {
                if (session_status() === PHP_SESSION_NONE) {
                    session_start();
                }
                $preview = $_SESSION['generated_preview'] ?? [];
                $indices = $postData['save_indices'] ?? [];

                $saved = 0;
                foreach ($preview as $i => $item) {
                    if (in_array((string) $i, (array) $indices, true) || ($postData['save_all'] ?? '') === '1') {
                        try {
                            $repo->insert($item);
                            $saved++;
                        } catch (\Throwable $e) {
                            // Skip duplicates
                        }
                    }
                }
                unset($_SESSION['generated_preview']);

                $this->redirectWithMessage('/content', sprintf('%d posts saved.', $saved), 'success');
                return;
            }
        }

        // POST /content/edit/{id}
        if (preg_match('#^/content/edit/(\d+)$#', $subPath, $m) && $request->isPost()) {
            $id = (int) $m[1];
            $postData = $request->getPostData();
            $token = (string) ($postData['csrf_token'] ?? '');

            if ($this->verifyCsrfToken($token)) {
                $repo->update($id, [
                    'title'            => trim((string) ($postData['title'] ?? '')),
                    'slug'             => trim((string) ($postData['slug'] ?? '')),
                    'content'          => (string) ($postData['content'] ?? ''),
                    'excerpt'          => trim((string) ($postData['excerpt'] ?? '')),
                    'author'           => trim((string) ($postData['author'] ?? 'admin')),
                    'category'         => trim((string) ($postData['category'] ?? 'Uncategorized')),
                    'status'           => trim((string) ($postData['status'] ?? 'published')),
                    'published_date'   => trim((string) ($postData['published_date'] ?? date('Y-m-d H:i:s'))),
                    'meta_description' => trim((string) ($postData['meta_description'] ?? '')),
                ]);
                $this->redirectWithMessage('/content', 'Content updated.', 'success');
                return;
            }
        }

        // POST /content/delete/{id}
        if (preg_match('#^/content/delete/(\d+)$#', $subPath, $m) && $request->isPost()) {
            $postData = $request->getPostData();
            $token = (string) ($postData['csrf_token'] ?? '');

            if ($this->verifyCsrfToken($token)) {
                $repo->delete((int) $m[1]);
                $this->redirectWithMessage('/content', 'Content deleted.', 'success');
                return;
            }
        }

        // GET /content/edit/{id}
        if (preg_match('#^/content/edit/(\d+)$#', $subPath, $m)) {
            $entry = $repo->getById((int) $m[1]);
            if ($entry === null) {
                $this->redirectWithMessage('/content', 'Content not found.', 'error');
                return;
            }

            $response->setContentType('text/html; charset=utf-8');
            $response->renderTemplate($this->templateDir . '/content_edit.php', [
                'admin_path'  => $this->adminPath,
                'csrf_token'  => $this->generateCsrfToken(),
                'entry'       => $entry,
            ]);
            $response->send();
            return;
        }

        // GET /content/generate
        if ($subPath === '/content/generate') {
            $this->renderContentGenerate($response, $cmsProfile);
            return;
        }

        // GET /content — list
        $page = (int) ($request->getQueryParam('page') ?? '1');
        $result = $repo->getPaginated($cmsProfile, $page);

        $response->setContentType('text/html; charset=utf-8');
        $response->renderTemplate($this->templateDir . '/content.php', array_merge($result, [
            'admin_path'  => $this->adminPath,
            'csrf_token'  => $this->generateCsrfToken(),
            'cms_profile' => $cmsProfile,
        ]));
        $response->send();
    }

    private function renderContentGenerate(Response $response, string $cmsProfile, string $message = '', string $error = ''): void
    {
        $response->setContentType('text/html; charset=utf-8');
        $response->renderTemplate($this->templateDir . '/content_generate.php', [
            'admin_path'   => $this->adminPath,
            'csrf_token'   => $this->generateCsrfToken(),
            'cms_profile'  => $cmsProfile,
            'preview'      => [],
            'message'      => $message,
            'message_type' => $error !== '' ? 'error' : 'success',
            'error'        => $error,
        ]);
        $response->send();
    }

    /**
     * Handle the visitors/bot log page.
     */
    private function handleVisitors(Request $request, string $subPath): void
    {
        $visitorLogger = new VisitorLogger($this->db);
        $page = (int) ($request->getQueryParam('page') ?? '1');
        $filters = [
            'type'     => $request->getQueryParam('type') ?? '',
            'bot_name' => $request->getQueryParam('bot_name') ?? '',
            'ip'       => $request->getQueryParam('ip') ?? '',
        ];

        $result = $visitorLogger->getPaginated($page, 50, $filters);
        $stats = $visitorLogger->getStats(24);

        $response = new Response();
        $response->setContentType('text/html; charset=utf-8');
        $response->renderTemplate($this->templateDir . '/visitors.php', array_merge($result, [
            'admin_path' => $this->adminPath,
            'csrf_token' => $this->generateCsrfToken(),
            'filters'    => $filters,
            'stats'      => $stats,
        ]));
        $response->send();
    }

    /**
     * Handle the updates page and update actions.
     */
    private function handleUpdates(Request $request, string $subPath): void
    {
        $checker = new \ReportedIp\Honeypot\Update\UpdateChecker($this->config);
        $manager = new \ReportedIp\Honeypot\Update\UpdateManager($this->config);

        // POST actions
        if ($request->isPost()) {
            $postData = $request->getPostData();
            $token = (string) ($postData['csrf_token'] ?? '');

            if (!$this->verifyCsrfToken($token)) {
                $this->redirectWithMessage('/updates', 'Invalid form submission.', 'error');
                return;
            }

            if ($subPath === '/updates/check') {
                try {
                    $result = $checker->forceCheck();
                    if ($result['available']) {
                        $this->redirectWithMessage('/updates', 'Update available: v' . $result['latest_version'], 'success');
                    } else {
                        $this->redirectWithMessage('/updates', 'You are running the latest version.', 'success');
                    }
                } catch (\Throwable $e) {
                    $this->redirectWithMessage('/updates', 'Check failed: ' . $e->getMessage(), 'error');
                }
                return;
            }

            if ($subPath === '/updates/apply') {
                $status = $checker->loadStatus();
                $downloadUrl = $status['latest_download_url'] ?? '';
                $targetVersion = $status['latest_version'] ?? '';

                if ($downloadUrl === '' || $targetVersion === '') {
                    $this->redirectWithMessage('/updates', 'No update available to apply.', 'error');
                    return;
                }

                try {
                    $result = $manager->update($targetVersion, $downloadUrl);
                    if ($result['success']) {
                        $this->redirectWithMessage('/updates', $result['message'], 'success');
                    } else {
                        $this->redirectWithMessage('/updates', $result['message'], 'error');
                    }
                } catch (\Throwable $e) {
                    $this->redirectWithMessage('/updates', 'Update failed: ' . $e->getMessage(), 'error');
                }
                return;
            }

            if ($subPath === '/updates/toggle-auto') {
                $status = $checker->loadStatus();
                $currentAuto = $status['auto_update_enabled'] ?? true;
                $status['auto_update_enabled'] = !$currentAuto;
                $checker->saveStatus($status);
                $label = !$currentAuto ? 'enabled' : 'disabled';
                $this->redirectWithMessage('/updates', 'Auto-update ' . $label . '.', 'success');
                return;
            }

            if ($subPath === '/updates/rollback') {
                $backupName = trim((string) ($postData['backup_name'] ?? ''));
                if ($backupName === '') {
                    $this->redirectWithMessage('/updates', 'No backup selected.', 'error');
                    return;
                }

                // Sanitize: only allow alphanumeric, dash, underscore, dot
                if (!preg_match('/^[a-zA-Z0-9._-]+$/', $backupName)) {
                    $this->redirectWithMessage('/updates', 'Invalid backup name.', 'error');
                    return;
                }

                $backups = $manager->getBackups();
                $backupPath = '';
                foreach ($backups as $b) {
                    if ($b['name'] === $backupName) {
                        $backupPath = $b['path'];
                        break;
                    }
                }

                if ($backupPath === '') {
                    $this->redirectWithMessage('/updates', 'Backup not found.', 'error');
                    return;
                }

                $result = $manager->rollback($backupPath);
                $this->redirectWithMessage('/updates', $result['message'], $result['success'] ? 'success' : 'error');
                return;
            }

            // Unknown POST action
            $this->redirectWithMessage('/updates', 'Unknown action.', 'error');
            return;
        }

        // GET: Render updates page
        $flashMessage = '';
        $flashType = '';
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        if (isset($_SESSION['flash_message'])) {
            $flashMessage = $_SESSION['flash_message'];
            $flashType = $_SESSION['flash_type'] ?? 'success';
            unset($_SESSION['flash_message'], $_SESSION['flash_type']);
        }

        $response = new Response();
        $response->setContentType('text/html; charset=utf-8');
        $response->renderTemplate($this->templateDir . '/updates.php', [
            'admin_path'      => $this->adminPath,
            'csrf_token'      => $this->generateCsrfToken(),
            'active_tab'      => 'updates',
            'update_status'   => $checker->loadStatus(),
            'current_version' => $checker->getCurrentVersion(),
            'preflight'       => $manager->preflightCheck(),
            'backups'         => $manager->getBackups(),
            'message'         => $flashMessage,
            'message_type'    => $flashType,
        ]);
        $response->send();
    }

    /**
     * Redirect to an admin sub-path with a flash message.
     */
    private function redirectWithMessage(string $subPath, string $message, string $type): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        $_SESSION['flash_message'] = $message;
        $_SESSION['flash_type'] = $type;

        $response = new Response();
        $response->redirect($this->adminPath . $subPath);
        $response->send();
    }

    /**
     * Generate a CSRF token and store it in the session.
     */
    private function generateCsrfToken(): string
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $token = bin2hex(random_bytes(32));
        $_SESSION['csrf_token'] = $token;
        $_SESSION['csrf_time'] = time();

        return $token;
    }

    /**
     * Verify a submitted CSRF token.
     */
    private function verifyCsrfToken(string $token): bool
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        if (empty($token) || !isset($_SESSION['csrf_token'])) {
            return false;
        }

        // Token expires after session lifetime (default 1 hour)
        $csrfLifetime = (int) $this->config->get('session_lifetime', 3600);
        if (isset($_SESSION['csrf_time']) && $_SESSION['csrf_time'] < time() - $csrfLifetime) {
            unset($_SESSION['csrf_token'], $_SESSION['csrf_time']);
            return false;
        }

        return hash_equals($_SESSION['csrf_token'], $token);
    }

    /**
     * Emit security headers for all admin panel responses.
     */
    private function sendSecurityHeaders(): void
    {
        if (headers_sent()) {
            return;
        }

        header('X-Frame-Options: DENY');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: same-origin');
        header('Cache-Control: no-store, no-cache, must-revalidate');
        header('Pragma: no-cache');
        header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'");
        header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
    }
}
