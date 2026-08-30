<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Core;

use ReportedIp\Honeypot\Detection\BotDetector;
use ReportedIp\Honeypot\Detection\DetectionPipeline;
use ReportedIp\Honeypot\Detection\Honeytoken;
use ReportedIp\Honeypot\Network\IpResolver;
use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Persistence\Logger;
use ReportedIp\Honeypot\Persistence\VisitorLogger;
use ReportedIp\Honeypot\Persistence\Whitelist;
use ReportedIp\Honeypot\Admin\AdminController;
use ReportedIp\Honeypot\Profile\CmsProfile;
use ReportedIp\Honeypot\Profile\DrupalProfile;
use ReportedIp\Honeypot\Profile\JoomlaProfile;
use ReportedIp\Honeypot\Profile\WordPressProfile;
use ReportedIp\Honeypot\Api\WebCronProcessor;
use ReportedIp\Honeypot\Trap;
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
        $this->maybeSeedDefaults();
    }

    /**
     * One-shot seed of WordPress install defaults for legacy installs.
     *
     * Marker file in the data directory makes this a no-op after the first run.
     */
    private function maybeSeedDefaults(): void
    {
        if ($this->profile->getName() !== 'wordpress') {
            return;
        }

        $dbPath = (string) $this->config->get('db_path', '');
        if ($dbPath === '') {
            return;
        }
        $dataDir = dirname($dbPath);

        try {
            $repo = new \ReportedIp\Honeypot\Content\ContentRepository($this->db);
            $language = (string) $this->config->get('content_language', 'en');
            \ReportedIp\Honeypot\Content\WordPressDefaults::seedIfNeeded($repo, $dataDir, $language);
        } catch (\Throwable $e) {
            // Silently ignore — seeding is best-effort and never blocks request handling.
        }
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

        // Static assets embedded in honeypot templates: skip detection + visitor logging
        $isStaticAsset = (bool) preg_match(
            '#\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map)$#i',
            $request->getPath()
        );

        if (!$isWhitelisted && !$isStaticAsset) {
            // Legitimate bots on content/home/misc pages skip detection
            if (in_array($routeType, ['content', 'home', 'misc'], true)
                && BotDetector::isLegitimateBot($request->getUserAgent())) {
                $isSafeBot = true;
            }

            if (!$isSafeBot) {
                // Run detection pipeline on every non-admin, non-whitelisted, non-safe-bot request
                $pipeline = DetectionPipeline::createDefault();
                $results = $pipeline->analyze($request);

                // Honeytoken reuse: replay of a leaked canary credential is a
                // confirmed-malicious signal regardless of what else matched.
                $honeytokenResult = (new Honeytoken($this->db))
                    ->detectReuse($this->buildHoneytokenHaystack($request), $request->getIp());
                if ($honeytokenResult !== null) {
                    $results[] = $honeytokenResult;
                }

                // Log detections
                if (!empty($results)) {
                    $this->logger->log($request, $results);
                }
            }
        }

        // Tarpit: slow down confirmed time-based blind SQL injection so the
        // attacker's tool "confirms" the injection and wastes its own time.
        $this->maybeTarpit($request);

        // Log visitor type for bot statistics (only for real page requests, not assets)
        if (!$isStaticAsset) {
            $this->logVisitor($request, $results, $routeType);
        }

        // Serve appropriate trap response regardless of whitelist status
        $this->serveTrap($request, $router);

        // Post-response processing: flush to client first, then run
        // webhooks and web cron without delaying the trap response
        $this->flushResponse();
        $this->dispatchWebhooks($request, $results);
        $this->processWebCron();
    }

    /**
     * Forward detections to user-configured webhook endpoints.
     *
     * @param array<int, \ReportedIp\Honeypot\Detection\DetectionResult> $results
     */
    private function dispatchWebhooks(Request $request, array $results): void
    {
        if (empty($results)) {
            return;
        }

        try {
            $repository = new \ReportedIp\Honeypot\Persistence\WebhookRepository($this->db);
            $dispatcher = new \ReportedIp\Honeypot\Api\WebhookDispatcher($repository, $this->config);
            $dispatcher->dispatch($request, $results);
        } catch (\Throwable $e) {
            // Webhook-Fehler dürfen die Honeypot-Funktion nie beeinträchtigen
        }
    }

    /**
     * Build the string scanned for honeytoken reuse: URI, body, POST values,
     * cookies and the Authorization header.
     */
    private function buildHoneytokenHaystack(Request $request): string
    {
        $parts = [$request->getUri(), $request->getBody()];

        foreach ($request->getPostData() as $value) {
            if (is_scalar($value)) {
                $parts[] = (string) $value;
            }
        }
        foreach ($request->getCookies() as $value) {
            $parts[] = $value;
        }
        $auth = $request->getHeader('Authorization');
        if ($auth !== null) {
            $parts[] = $auth;
        }

        return implode("\n", $parts);
    }

    /**
     * Delay the response when the request carries a time-based blind SQL
     * injection payload (SLEEP, pg_sleep, BENCHMARK, WAITFOR DELAY).
     */
    private function maybeTarpit(Request $request): void
    {
        if (!(bool) $this->config->get('tarpit_enabled', true)) {
            return;
        }

        $haystack = $request->getUri() . "\n" . $request->getBody();
        if (!preg_match(
            '/\b(sleep|pg_sleep|benchmark)\s*\(|waitfor\s+delay|dbms_pipe\.receive_message/i',
            $haystack
        )) {
            return;
        }

        $maxSeconds = (int) $this->config->get('tarpit_max_seconds', 6);
        $maxSeconds = max(1, min(15, $maxSeconds));
        usleep(random_int(2_000_000, $maxSeconds * 1_000_000));
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
     * Load the CMS profile based on configuration (falls back to WordPress).
     */
    private function loadProfile(string $profileName): CmsProfile
    {
        $profile = match (strtolower(trim($profileName))) {
            'drupal' => new DrupalProfile(),
            'joomla' => new JoomlaProfile(),
            default  => new WordPressProfile(),
        };
        $profile->setConfig($this->config->all());

        return $profile;
    }

    /**
     * Register all available trap handlers.
     */
    private function registerTraps(): void
    {
        $traps = [
            new Trap\ContentTrap(),
            new Trap\LoginTrap(),
            new Trap\AdminTrap(),
            new Trap\RestApiTrap(),
            new Trap\XmlRpcTrap(),
            new Trap\FakeVulnTrap(),
            new Trap\CommentTrap(),
            new Trap\SearchTrap(),
            new Trap\RegistrationTrap(),
            new Trap\ContactFormTrap(),
            new Trap\HomeTrap(),
            new Trap\NotFoundTrap(),
            new Trap\MiscTrap(),
            new Trap\SourceLeakTrap(),
            new Trap\DbAdminTrap(),
            new Trap\SystemInfoTrap(),
            new Trap\WebshellTrap(),
        ];

        foreach ($traps as $trap) {
            if ($trap instanceof DatabaseAwareInterface) {
                $trap->setDatabase($this->db);
            }
            $this->traps[$trap->getName()] = $trap;
        }
    }

    /**
     * Serve the trap response based on the route.
     */
    private function serveTrap(Request $request, Router $router): void
    {
        $route = $router->route($request);
        $response = new Response();

        $trap = $this->traps[$route['trap']] ?? $this->traps['not_found'];
        $trap->handle($request, $response, $this->profile)->send();
    }

    /**
     * Handle requests to the honeypot admin panel.
     */
    private function handleAdmin(Request $request): void
    {
        $controller = new AdminController($this->config, $this->db, $this->logger, $this->whitelist);
        $controller->handle($request);
    }

    /**
     * Log visitor classification for bot statistics.
     *
     * @param array<int, \ReportedIp\Honeypot\Detection\DetectionResult> $detectionResults
     */
    private function logVisitor(Request $request, array $detectionResults, string $routeType): void
    {
        // Trap routes have no legitimate purpose on a honeypot — any UA hitting them is suspect.
        // Good bots and AI agents are still preserved (a Googlebot probing /wp-login.php stays good_bot).
        $suspiciousRoutes = ['login', 'admin', 'vuln', 'register', 'xmlrpc', 'api'];

        try {
            $classification = BotDetector::classify($request->getUserAgent());
            $visitorType = $classification['type'];
            $botName = $classification['name'];

            // Override to 'hacker' if detection pipeline found threats
            // but preserve classification for known good bots and AI agents
            if (!empty($detectionResults) && !in_array($visitorType, ['good_bot', 'ai_agent'], true)) {
                $visitorType = 'hacker';
            }

            // Route-based override: visiting trap routes alone is enough to classify as hacker
            if (in_array($routeType, $suspiciousRoutes, true)
                && !in_array($visitorType, ['good_bot', 'ai_agent', 'hacker'], true)) {
                $visitorType = 'hacker';
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

}
