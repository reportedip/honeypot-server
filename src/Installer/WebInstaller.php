<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Installer;

/**
 * reportedip-honeypot-server Web Installer
 *
 * Handles the initial setup and configuration via a web interface.
 */
class WebInstaller
{
    private string $baseDir;
    private string $configFile;

    public function __construct(string $baseDir)
    {
        $this->baseDir = $baseDir;
        $this->configFile = $baseDir . '/config/config.php';
    }

    public function run(): void
    {
        // Security check: If config exists, do not run installer
        if (file_exists($this->configFile)) {
            header('Location: /');
            exit;
        }

        // Handle form submission
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $this->handlePost();
            return;
        }

        // Display the installation form
        $this->renderForm();
    }

    private function handlePost(): void
    {
        $errors = [];

        // 1. Validate System Requirements
        if (version_compare(PHP_VERSION, '8.2.0', '<')) {
            $errors[] = 'PHP 8.2 or higher is required.';
        }
        if (!extension_loaded('pdo_sqlite')) {
            $errors[] = 'The pdo_sqlite extension is required.';
        }
        if (!extension_loaded('curl')) {
            $errors[] = 'The curl extension is required.';
        }
        if (!extension_loaded('json')) {
            $errors[] = 'The json extension is required.';
        }

        // 2. Validate Input
        $apiKey = trim($_POST['api_key'] ?? '');
        $cmsProfile = $_POST['cms_profile'] ?? 'wordpress';
        $adminPath = trim($_POST['admin_path'] ?? '/_hp_admin');
        $password = $_POST['admin_password'] ?? '';
        $openaiKey = trim($_POST['openai_key'] ?? '');
        $openaiBaseUrl = trim($_POST['openai_base_url'] ?? 'https://api.openai.com/v1');
        $openaiModel = trim($_POST['openai_model'] ?? 'gpt-4o-mini');
        $contentLanguage = $_POST['content_language'] ?? 'en';

        if (empty($apiKey)) {
            $errors[] = 'Community Access Key is required.';
        } elseif (strlen($apiKey) !== 64) {
             // Warning only, or strict? The CLI script just warned. Let's be strict for better UX.
             // Actually, CLI said "Warning: Key should be 64 characters. Continuing anyway."
             // So we'll allow it but maybe show a warning? For simplicity, let's enforce it if it's clearly wrong length
             // but allow if it's close? No, let's stick to the CLI logic: allow it but maybe warn.
             // For the web installer, let's just proceed.
        }

        if (empty($password)) {
             $errors[] = 'Admin Password is required.';
        }

        if (!str_starts_with($adminPath, '/')) {
            $adminPath = '/' . $adminPath;
        }

        if (!empty($errors)) {
            $this->renderForm($errors, $_POST);
            return;
        }

        // 3. Create Config
        try {
            $this->createConfig($apiKey, $cmsProfile, $adminPath, $password, $openaiKey, $openaiBaseUrl, $openaiModel, $contentLanguage);
            $this->initializeSystem();

            // Success!
            $this->renderSuccess($adminPath);
        } catch (\Throwable $e) {
            $this->renderForm(['Installation failed: ' . $e->getMessage()], $_POST);
        }
    }

    private function createConfig(
        string $apiKey,
        string $cmsProfile,
        string $adminPath,
        string $password,
        string $openaiKey,
        string $openaiBaseUrl,
        string $openaiModel,
        string $contentLanguage
    ): void {
        $passwordHash = password_hash($password, PASSWORD_BCRYPT);

        $configValues = [
            'api_key'             => $apiKey,
            'api_url'             => 'https://reportedip.de/wp-json/reportedip/v2/report',
            'cms_profile'         => $cmsProfile,
            'admin_path'          => $adminPath,
            'admin_password_hash' => $passwordHash,
            'db_path'             => "__DIR__ . '/../data/honeypot.sqlite'",
            'cache_path'          => "__DIR__ . '/../data/cache'",
            'cache_ttl'           => 3600,
            'rate_limit_per_ip'   => 10,
            'report_rate_limit'   => 60,
            'report_batch_size'   => 10,
            'queue_mode'          => 'web',
            'whitelist_own_ip'    => true,
            'trusted_proxies'     => [
                '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
                '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
                '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
                '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
                '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
            ],
            'debug'               => false,
            'log_retention_days'  => 90,
            'session_lifetime'    => 3600,
            'log_human_visitors'  => false,
            'ca_bundle'           => '',
            'openai_api_key'      => $openaiKey,
            'openai_base_url'     => $openaiBaseUrl,
            'openai_model'        => $openaiModel,
            'content_language'    => $contentLanguage,
            'content_niche'       => '',
            'auto_update'         => true,
            'update_check_interval' => 10800,
        ];

        $lines = ["<?php\n"];
        $lines[] = "declare(strict_types=1);\n";
        $lines[] = "";
        $lines[] = "/**";
        $lines[] = " * reportedip-honeypot-server Configuration";
        $lines[] = " * Generated by WebInstaller on " . date('Y-m-d H:i:s');
        $lines[] = " */\n";
        $lines[] = "return [";

        foreach ($configValues as $key => $value) {
            if ($key === 'openai_api_key') {
                $lines[] = "";
                $lines[] = "    // AI Content Generation";
            }
            if ($key === 'db_path' || $key === 'cache_path') {
                // Expression values (not string literals)
                $lines[] = "    '{$key}' => {$value},";
            } elseif (is_array($value)) {
                $lines[] = "    '{$key}' => [";
                foreach ($value as $item) {
                    $lines[] = "        " . var_export($item, true) . ",";
                }
                $lines[] = "    ],";
            } elseif (is_bool($value)) {
                $lines[] = "    '{$key}' => " . ($value ? 'true' : 'false') . ",";
            } elseif (is_int($value)) {
                $lines[] = "    '{$key}' => {$value},";
            } else {
                $lines[] = "    '{$key}' => " . var_export($value, true) . ",";
            }
        }

        $lines[] = "];\n";

        if (file_put_contents($this->configFile, implode("\n", $lines)) === false) {
            throw new \RuntimeException("Cannot write to " . $this->configFile);
        }
    }

    private function initializeSystem(): void
    {
        // Create data directory
        $dataDir = $this->baseDir . '/data';
        if (!is_dir($dataDir)) {
            if (!mkdir($dataDir, 0775, true)) {
                throw new \RuntimeException("Cannot create directory " . $dataDir);
            }
        }

        // Create cache directory
        $cacheDir = $dataDir . '/cache';
        if (!is_dir($cacheDir)) {
             if (!mkdir($cacheDir, 0775, true)) {
                throw new \RuntimeException("Cannot create directory " . $cacheDir);
             }
        }

        // Create protective files
        $htaccess = $dataDir . '/.htaccess';
        if (!file_exists($htaccess)) {
            $content = implode("\n", [
                '# Deny all access to data directory',
                'Require all denied',
                '',
                '# Fallback for Apache 2.2',
                '<IfModule !mod_authz_core.c>',
                '    Order deny,allow',
                '    Deny from all',
                '</IfModule>',
                '',
            ]);
            file_put_contents($htaccess, $content);
        }

        $indexPhp = $dataDir . '/index.php';
        if (!file_exists($indexPhp)) {
            file_put_contents($indexPhp, "<?php\n// Silence is golden.\nhttp_response_code(403);\nexit;\n");
        }

        // Initialize SQLite database
        // We use the existing Database class, but we need to make sure it's loaded.
        // The autoloader in index.php should handle this.
        if (class_exists('\\ReportedIp\\Honeypot\\Persistence\\Database')) {
             $db = new \ReportedIp\Honeypot\Persistence\Database($dataDir . '/honeypot.sqlite');
             $db->initialize();

             // Whitelist Server IP
             $serverIps = [];
             $serverIps[] = '127.0.0.1';
             $serverIps[] = '::1';
             if (isset($_SERVER['SERVER_ADDR'])) {
                 $serverIps[] = $_SERVER['SERVER_ADDR'];
             }
             // Try to get public IP via external service if possible? No, stick to local for now.

             $whitelist = new \ReportedIp\Honeypot\Persistence\Whitelist($db);
             foreach (array_unique($serverIps) as $ip) {
                 $whitelist->add($ip, 'Server IP (auto-added by installer)');
             }
        } else {
            throw new \RuntimeException("Database class not found. Autoloader issue?");
        }
    }

    private function renderForm(array $errors = [], array $values = []): void
    {
        $phpVersion = PHP_VERSION;
        $phpOk = version_compare($phpVersion, '8.2.0', '>=');

        $extPdo = extension_loaded('pdo_sqlite');
        $extCurl = extension_loaded('curl');
        $extJson = extension_loaded('json');

        $systemOk = $phpOk && $extPdo && $extCurl && $extJson;

        $defaults = [
            'api_key' => '',
            'cms_profile' => 'wordpress',
            'admin_path' => '/_hp_admin',
            'openai_key' => '',
            'openai_base_url' => 'https://api.openai.com/v1',
            'openai_model' => 'gpt-4o-mini',
            'content_language' => 'en',
        ];

        $values = array_merge($defaults, $values);

        ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReportedIP Honeypot Installation</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; background: #f0f2f5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 40px auto; background: #fff; padding: 40px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        h1 { margin-top: 0; color: #1a202c; text-align: center; }
        .step { margin-bottom: 30px; border-bottom: 1px solid #eee; padding-bottom: 20px; }
        .step:last-child { border-bottom: none; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; font-weight: 500; }
        input[type="text"], input[type="password"], select { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; font-size: 16px; }
        .hint { font-size: 0.85em; color: #666; margin-top: 5px; }
        button { background: #007bff; color: #fff; border: none; padding: 12px 24px; border-radius: 4px; cursor: pointer; font-size: 16px; width: 100%; font-weight: bold; transition: background 0.2s; }
        button:hover { background: #0056b3; }
        button:disabled { background: #ccc; cursor: not-allowed; }
        .error-summary { background: #fee2e2; border: 1px solid #ef4444; color: #b91c1c; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
        .check-item { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #eee; }
        .check-pass { color: #10b981; font-weight: bold; }
        .check-fail { color: #ef4444; font-weight: bold; }
        .optional-section { background: #f9fafb; padding: 15px; border-radius: 4px; margin-top: 10px; border: 1px solid #e5e7eb; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Honeypot Installation</h1>

        <?php if (!empty($errors)): ?>
            <div class="error-summary">
                <strong>Installation Failed:</strong>
                <ul>
                    <?php foreach ($errors as $error): ?>
                        <li><?php echo htmlspecialchars($error); ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <div class="step">
            <h2>1. System Check</h2>
            <div class="check-item">
                <span>PHP Version (>= 8.2)</span>
                <span class="<?php echo $phpOk ? 'check-pass' : 'check-fail'; ?>"><?php echo $phpVersion; ?></span>
            </div>
            <div class="check-item">
                <span>PDO SQLite</span>
                <span class="<?php echo $extPdo ? 'check-pass' : 'check-fail'; ?>"><?php echo $extPdo ? 'OK' : 'Missing'; ?></span>
            </div>
            <div class="check-item">
                <span>cURL</span>
                <span class="<?php echo $extCurl ? 'check-pass' : 'check-fail'; ?>"><?php echo $extCurl ? 'OK' : 'Missing'; ?></span>
            </div>
            <div class="check-item">
                <span>JSON</span>
                <span class="<?php echo $extJson ? 'check-pass' : 'check-fail'; ?>"><?php echo $extJson ? 'OK' : 'Missing'; ?></span>
            </div>
        </div>

        <?php if ($systemOk): ?>
            <form method="post">
                <div class="step">
                    <h2>2. Configuration</h2>

                    <div style="background:#EEF2FF; border:1px solid #C7D2FE; color:#3730A3; padding:12px 16px; border-radius:6px; margin-bottom:20px; font-size:0.9em; line-height:1.5;">
                        <strong>Join our community!</strong> We are looking for testers and contributors to help improve the data quality of <a href="https://reportedip.de" target="_blank" style="color:#4F46E5;">reportedip.de</a>.
                        Every honeypot installation helps protect the community.<br>
                        <strong>You need a Community Access Key (API key) to report attacks.</strong>
                        Please contact <a href="mailto:1@reportedip.de" style="color:#4F46E5; font-weight:bold;">1@reportedip.de</a> to request your free key.
                    </div>

                    <div class="form-group">
                        <label for="api_key">Community Access Key</label>
                        <input type="text" id="api_key" name="api_key" value="<?php echo htmlspecialchars($values['api_key']); ?>" required placeholder="64-character hex string">
                        <div class="hint">Don't have a key yet? Contact <a href="mailto:1@reportedip.de">1@reportedip.de</a> to get one (free).</div>
                    </div>

                    <div class="form-group">
                        <label for="cms_profile">CMS Profile</label>
                        <select id="cms_profile" name="cms_profile">
                            <option value="wordpress" <?php echo $values['cms_profile'] === 'wordpress' ? 'selected' : ''; ?>>WordPress (Default)</option>
                            <option value="drupal" <?php echo $values['cms_profile'] === 'drupal' ? 'selected' : ''; ?>>Drupal</option>
                            <option value="joomla" <?php echo $values['cms_profile'] === 'joomla' ? 'selected' : ''; ?>>Joomla</option>
                        </select>
                        <div class="hint">Which CMS should the honeypot emulate?</div>
                    </div>

                    <div class="form-group">
                        <label for="admin_path">Admin Panel Path</label>
                        <input type="text" id="admin_path" name="admin_path" value="<?php echo htmlspecialchars($values['admin_path']); ?>" required>
                        <div class="hint">The URL path to access your honeypot dashboard.</div>
                    </div>

                    <div class="form-group">
                        <label for="admin_password">Admin Password</label>
                        <input type="password" id="admin_password" name="admin_password" required>
                    </div>
                </div>

                <div class="step">
                    <h2>3. AI Content (Optional)</h2>
                    <div class="optional-section">
                        <div class="form-group">
                            <label for="openai_key">OpenAI API Key</label>
                            <input type="password" id="openai_key" name="openai_key" value="<?php echo htmlspecialchars($values['openai_key']); ?>" placeholder="sk-...">
                            <div class="hint">Leave empty to skip AI content generation.</div>
                        </div>

                        <div class="form-group">
                            <label for="openai_model">Model</label>
                            <input type="text" id="openai_model" name="openai_model" value="<?php echo htmlspecialchars($values['openai_model']); ?>">
                        </div>

                         <div class="form-group">
                            <label for="content_language">Content Language</label>
                            <select id="content_language" name="content_language">
                                <option value="en" <?php echo $values['content_language'] === 'en' ? 'selected' : ''; ?>>English</option>
                                <option value="de" <?php echo $values['content_language'] === 'de' ? 'selected' : ''; ?>>German</option>
                            </select>
                        </div>
                    </div>
                </div>

                <button type="submit">Install Honeypot</button>
            </form>
        <?php else: ?>
            <div class="error-summary">
                Please resolve the system requirements above to proceed with installation.
            </div>
            <button disabled>Install Honeypot</button>
        <?php endif; ?>
    </div>
</body>
</html>
        <?php
    }

    private function renderSuccess(string $adminPath): void
    {
        ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Installation Complete</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; background: #f0f2f5; margin: 0; padding: 20px; }
        .container { max-width: 600px; margin: 40px auto; background: #fff; padding: 40px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); text-align: center; }
        h1 { color: #10b981; margin-top: 0; }
        .btn { display: inline-block; background: #007bff; color: #fff; text-decoration: none; padding: 12px 24px; border-radius: 4px; font-weight: bold; margin-top: 20px; }
        .btn:hover { background: #0056b3; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Installation Complete!</h1>
        <p>The honeypot server has been successfully installed and configured.</p>
        <p>You can now access your admin dashboard.</p>
        <a href="<?php echo htmlspecialchars($adminPath); ?>" class="btn">Go to Admin Panel</a>

        <p style="margin-top: 30px; font-size: 0.9em; color: #666;">
            <strong>Note:</strong> The report queue is processed automatically during page visits (web cron mode). For high-traffic installations, switch to <code>'queue_mode' =&gt; 'cron'</code> in config/config.php and set up a cron job.
        </p>
    </div>
</body>
</html>
        <?php
    }
}
