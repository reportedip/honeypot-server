<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Core;

use ReportedIp\Honeypot\Detection\BotDetector;
use ReportedIp\Honeypot\Detection\DetectionPipeline;
use ReportedIp\Honeypot\Network\IpResolver;
use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Persistence\Logger;
use ReportedIp\Honeypot\Persistence\VisitorLogger;
use ReportedIp\Honeypot\Persistence\Whitelist;
use ReportedIp\Honeypot\Profile\CmsProfile;
use ReportedIp\Honeypot\Profile\ProfileFactory;
use ReportedIp\Honeypot\Api\WebCronProcessor;
use ReportedIp\Honeypot\Trap\DatabaseAwareInterface;
use ReportedIp\Honeypot\Trap\TrapInterface;

/**
 * Main application bootstrap and request lifecycle manager.
 *
 * Coordinates the full request flow: IP resolution, whitelist checking,
 * routing, detection analysis, logging, and trap response rendering.
 */
final class App
{
    private readonly Config $config;
    private readonly Database $db;
    private readonly CmsProfile $profile;
    private readonly Logger $logger;
    private readonly Whitelist $whitelist;

    /** @var array<string, TrapInterface> */
    private array $traps = [];

    public function __construct(Config $config)
    {
        $this->config = $config;
        $this->db = new Database($config->get('db_path', __DIR__ . '/../../data/honeypot.sqlite'));
        $this->db->initialize();

        $this->profile = $this->loadProfile($config->get('cms_profile', 'wordpress'));
        $this->logger = new Logger($this->db, $config);
        $this->whitelist = new Whitelist($this->db);
        $this->registerTraps();
    }

    /**
     * Handle an incoming request through the full honeypot lifecycle.
     */
    public function handle(): void
    {
        $request = Request::fromGlobals();

        // Resolve real client IP
        $ipResolver = new IpResolver($this->config);
        $request->setIp($ipResolver->resolve($request));

        // Set the site URL on the profile for absolute URLs in responses
        $this->profile->setSiteUrl($request->getBaseUrl());

        // Route the request
        $router = new Router($this->profile, $this->config);

        // Admin panel path -- handled separately
        if ($router->isAdminPath($request)) {
            $this->handleAdmin($request);
            return;
        }

        // Check whitelist -- serve trap content but do not log or report
        $isWhitelisted = $this->whitelist->isWhitelisted($request->getIp());
        $isSafeBot = false;
        $results = [];

        // Determine route type for bot-safe routing
        $routeType = $this->profile->matchRoute(
            $request->getPath(),
            $request->getMethod(),
            $request->getQueryParams()
        );

        if (!$isWhitelisted) {
            // Legitimate bots on content/home/misc pages skip detection
            if (in_array($routeType, ['content', 'home', 'misc'], true)
                && BotDetector::isLegitimateBot($request->getUserAgent())) {
                $isSafeBot = true;
            }

            if (!$isSafeBot) {
                // Run detection pipeline on every non-admin, non-whitelisted, non-safe-bot request
                $pipeline = DetectionPipeline::createDefault();
                $results = $pipeline->analyze($request);

                // Log detections
                if (!empty($results)) {
                    $this->logger->log($request, $results);
                }
            }
        }

        // Log visitor type for bot statistics
        $this->logVisitor($request, $results, $routeType);

        // Serve appropriate trap response regardless of whitelist status
        $this->serveTrap($request, $router);

        // Process web cron (after response is sent to client)
        $this->processWebCron();
    }

    /**
     * Get the database instance (for CLI tools and admin panel).
     */
    public function getDatabase(): Database
    {
        return $this->db;
    }

    /**
     * Get the logger instance (for CLI tools and admin panel).
     */
    public function getLogger(): Logger
    {
        return $this->logger;
    }

    /**
     * Get the whitelist instance (for CLI tools and admin panel).
     */
    public function getWhitelist(): Whitelist
    {
        return $this->whitelist;
    }

    /**
     * Get the CMS profile instance.
     */
    public function getProfile(): CmsProfile
    {
        return $this->profile;
    }

    /**
     * Get the configuration instance.
     */
    public function getConfig(): Config
    {
        return $this->config;
    }

    /**
     * Load the CMS profile based on configuration.
     */
    private function loadProfile(string $profileName): CmsProfile
    {
        return ProfileFactory::create($profileName, $this->config->all());
    }

    /**
     * Register all available trap handlers.
     */
    private function registerTraps(): void
    {
        $trapClasses = [
            'ReportedIp\\Honeypot\\Trap\\ContentTrap',
            'ReportedIp\\Honeypot\\Trap\\LoginTrap',
            'ReportedIp\\Honeypot\\Trap\\AdminTrap',
            'ReportedIp\\Honeypot\\Trap\\RestApiTrap',
            'ReportedIp\\Honeypot\\Trap\\XmlRpcTrap',
            'ReportedIp\\Honeypot\\Trap\\FakeVulnTrap',
            'ReportedIp\\Honeypot\\Trap\\CommentTrap',
            'ReportedIp\\Honeypot\\Trap\\SearchTrap',
            'ReportedIp\\Honeypot\\Trap\\RegistrationTrap',
            'ReportedIp\\Honeypot\\Trap\\ContactFormTrap',
            'ReportedIp\\Honeypot\\Trap\\HomeTrap',
            'ReportedIp\\Honeypot\\Trap\\NotFoundTrap',
            'ReportedIp\\Honeypot\\Trap\\MiscTrap',
        ];

        foreach ($trapClasses as $className) {
            if (class_exists($className)) {
                /** @var TrapInterface $trap */
                $trap = new $className();
                if ($trap instanceof DatabaseAwareInterface) {
                    $trap->setDatabase($this->db);
                }
                $this->traps[$trap->getName()] = $trap;
            }
        }
    }

    /**
     * Serve the trap response based on the route.
     */
    private function serveTrap(Request $request, Router $router): void
    {
        $route = $router->route($request);
        $response = new Response();

        // Map route trap names to Trap class names
        $trapMapping = [
            'content'       => 'content',
            'login'         => 'login',
            'cms_admin'     => 'admin',
            'api'           => 'rest_api',
            'xmlrpc'        => 'xmlrpc',
            'vulnerability' => 'fake_vuln',
            'comment'       => 'comment',
            'search'        => 'search',
            'register'      => 'registration',
            'contact'       => 'contact',
            'home'          => 'home',
            'not_found'     => 'not_found',
            'misc'          => 'misc',
        ];

        $trapName = $trapMapping[$route['trap']] ?? $route['trap'];

        // Try to use a registered Trap class
        if (isset($this->traps[$trapName])) {
            $response = $this->traps[$trapName]->handle($request, $response, $this->profile);
            $response->send();
            return;
        }

        // Fallback: template-based rendering
        $this->serveTrapFallback($request, $response, $route);
    }

    /**
     * Fallback trap serving using direct template rendering.
     *
     * Used when Trap classes are not available.
     */
    private function serveTrapFallback(Request $request, Response $response, array $route): void
    {
        // Set CMS-specific default headers
        foreach ($this->profile->getDefaultHeaders() as $name => $value) {
            $response->setHeader($name, $value);
        }

        $templateDir = __DIR__ . '/../../templates/' . $this->profile->getTemplatePath();
        $templateData = array_merge($this->profile->getTemplateData(), [
            'request' => $request,
            'config'  => $this->config,
        ]);

        switch ($route['trap']) {
            case 'login':
                $response->setContentType('text/html; charset=utf-8');
                $templateFile = $templateDir . '/login.php';
                if (file_exists($templateFile)) {
                    $response->renderTemplate($templateFile, $templateData);
                } else {
                    $response->setBody($this->fallbackLoginPage());
                }
                break;

            case 'cms_admin':
                $response->redirect($this->profile->getLoginPath() . '?redirect_to=' . urlencode($request->getUri()));
                break;

            case 'api':
                $response->json([
                    'name'        => 'My Site',
                    'description' => 'Just another site',
                    'url'         => '',
                    'namespaces'  => ['wp/v2', 'oembed/1.0'],
                ]);
                break;

            case 'xmlrpc':
                $response->setContentType('text/xml; charset=utf-8');
                $response->setBody(
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    . '<methodResponse><params><param><value>'
                    . '<array><data><value><string>blogger.getUsersBlogs</string></value>'
                    . '</data></array></value></param></params></methodResponse>'
                );
                break;

            case 'home':
                $response->setContentType('text/html; charset=utf-8');
                $templateFile = $templateDir . '/home.php';
                if (file_exists($templateFile)) {
                    $response->renderTemplate($templateFile, $templateData);
                } else {
                    $response->setBody($this->fallbackLoginPage());
                }
                break;

            case 'not_found':
            default:
                $response->setStatusCode(404);
                $response->setContentType('text/html; charset=utf-8');
                $response->setBody('<html><body><h1>404 Not Found</h1></body></html>');
                break;
        }

        $response->send();
    }

    /**
     * Handle requests to the honeypot admin panel.
     */
    private function handleAdmin(Request $request): void
    {
        // Dynamic loading of AdminController if available
        $controllerClass = 'ReportedIp\\Honeypot\\Admin\\AdminController';
        if (class_exists($controllerClass)) {
            $controller = new $controllerClass($this->config, $this->db, $this->logger, $this->whitelist);
            $controller->handle($request);
            return;
        }

        // Fallback: basic admin panel not yet available
        $response = new Response();
        $response->setStatusCode(503);
        $response->setContentType('text/html; charset=utf-8');
        $response->setBody('<html><body><h1>Admin Panel</h1><p>Admin module not installed.</p></body></html>');
        $response->send();
    }

    /**
     * Log visitor classification for bot statistics.
     *
     * @param array<int, \ReportedIp\Honeypot\Detection\DetectionResult> $detectionResults
     */
    private function logVisitor(Request $request, array $detectionResults, string $routeType): void
    {
        try {
            $classification = BotDetector::classify($request->getUserAgent());
            $visitorType = $classification['type'];
            $botName = $classification['name'];

            // Override to 'hacker' if detection pipeline found threats
            if (!empty($detectionResults)) {
                $visitorType = 'hacker';
            }

            // Skip human visitors if configured to do so
            if ($visitorType === 'human' && !$this->config->get('log_human_visitors', false)) {
                return;
            }

            $visitorLogger = new VisitorLogger($this->db);
            $visitorLogger->log($request, $visitorType, $botName, $routeType);
        } catch (\Throwable $e) {
            // Silently ignore visitor logging errors
        }
    }

    /**
     * Flush the HTTP response to the client and continue processing in the background.
     */
    private function flushResponse(): void
    {
        if (function_exists('fastcgi_finish_request')) {
            fastcgi_finish_request();
            return;
        }

        ignore_user_abort(true);
        if (ob_get_level() > 0) {
            ob_end_flush();
        }
        flush();
    }

    /**
     * Process the report queue via web cron if enabled.
     */
    private function processWebCron(): void
    {
        if ($this->config->get('queue_mode', 'web') !== 'web') {
            return;
        }

        $this->flushResponse();

        try {
            $processor = new WebCronProcessor($this->db, $this->config);
            $processor->process();
        } catch (\Throwable $e) {
            // Silently ignore — errors logged to api_errors.log by ReportClient
        }

        try {
            $checker = new \ReportedIp\Honeypot\Update\UpdateChecker($this->config);
            $checker->maybeCheck();
        } catch (\Throwable $e) {
            // Silently ignore update check errors
        }
    }

    /**
     * Fallback login page when no template or trap class is available.
     */
    private function fallbackLoginPage(): string
    {
        return '<!DOCTYPE html><html><head><title>Log In</title></head>'
            . '<body><h1>Log In</h1>'
            . '<form method="post"><label>Username<br><input type="text" name="log"></label><br>'
            . '<label>Password<br><input type="password" name="pwd"></label><br>'
            . '<button type="submit">Log In</button></form></body></html>';
    }
}
