<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection;

/**
 * Central repository of regex patterns and string lists used by detection analyzers.
 *
 * All patterns are maintained here to prevent duplication, ensure consistency,
 * and allow easy updates. Patterns use PCRE syntax with the 'i' (case-insensitive)
 * flag applied by consumers where appropriate.
 */
final class PatternLibrary
{
    /**
     * SQL injection patterns covering UNION-based, error-based, blind,
     * time-based, and stacked query injection techniques.
     *
     * @return string[] Array of regex patterns.
     */
    public static function sqlInjectionPatterns(): array
    {
        return [
            // UNION-based injection
            '/union\s+(all\s+)?select/i',
            '/union\s+(all\s+)?select\s+.*from/i',

            // Boolean-based blind injection
            '/\bor\b\s+\d+=\d+/i',
            '/\band\b\s+\d+=\d+/i',
            "/\bor\b\s+'[^']*'\s*=\s*'[^']*'/i",
            "/\band\b\s+'[^']*'\s*=\s*'[^']*'/i",
            '/\bor\b\s+"[^"]*"\s*=\s*"[^"]*"/i',

            // Time-based blind injection
            '/sleep\s*\(\s*\d+/i',
            '/benchmark\s*\(\s*\d+/i',
            '/waitfor\s+delay\s/i',
            '/pg_sleep\s*\(/i',

            // Stacked queries
            '/;\s*(drop|insert|update|delete|alter|create|truncate)\s/i',

            // Comment-based injection
            '/\/\*.*?\*\//s',
            '/--\s*$/m',

            // Error-based injection
            '/\bhaving\b\s+\d/i',
            '/\bgroup\s+by\b\s+\d/i',
            '/\border\s+by\b\s+\d{2,}/i',
            '/extractvalue\s*\(/i',
            '/updatexml\s*\(/i',

            // Blind SQLi functions
            '/\bif\s*\(\s*\(/i',
            '/\bcase\s+when\b/i',
            '/\bsubstring\s*\(/i',
            '/\bascii\s*\(\s*substr/i',
            '/\bchar\s*\(\s*\d+/i',
            '/\bconcat\s*\(/i',
            '/\bconcat_ws\s*\(/i',
            '/\bgroup_concat\s*\(/i',

            // URL-encoded single quote / semicolon variants
            '/%27.*?(union|select|or|and|drop|insert|update|delete)/i',
            '/%22.*?(union|select|or|and|drop|insert|update|delete)/i',
            '/%3b\s*(drop|insert|update|delete)/i',

            // Double URL-encoded variants
            '/%2527/i',
            '/%2522/i',
            '/%253b/i',

            // Information schema probing
            '/information_schema\./i',
            '/table_name/i',
            '/column_name/i',

            // Database-specific functions
            '/load_file\s*\(/i',
            '/into\s+(out|dump)file/i',
            '/0x[0-9a-f]{8,}/i',
        ];
    }

    /**
     * XSS (Cross-Site Scripting) patterns covering reflected, stored,
     * and DOM-based XSS attack vectors.
     *
     * @return string[] Array of regex patterns.
     */
    public static function xssPatterns(): array
    {
        return [
            // Script tag injection (case variations)
            '/<\s*script[\s>]/i',
            '/<\s*\/\s*script\s*>/i',

            // Event handler injection
            '/\bon\w+\s*=\s*["\']?[^"\']*(?:alert|confirm|prompt|eval|function|javascript)/i',
            '/\bonerror\s*=/i',
            '/\bonload\s*=/i',
            '/\bonmouseover\s*=/i',
            '/\bonfocus\s*=/i',
            '/\bonclick\s*=/i',
            '/\bonchange\s*=/i',
            '/\bonsubmit\s*=/i',
            '/\bonmouseout\s*=/i',
            '/\bonkeyup\s*=/i',
            '/\bonkeydown\s*=/i',

            // JavaScript protocol
            '/javascript\s*:/i',

            // Data URI with script content
            '/data\s*:\s*text\/html/i',
            '/data\s*:\s*[^;]*;base64/i',

            // SVG-based XSS
            '/<\s*svg[\s\/].*?on\w+\s*=/is',
            '/<\s*svg\s/i',

            // IMG-based XSS
            '/<\s*img[^>]+on\w+\s*=/i',
            '/<\s*img[^>]+src\s*=\s*["\']?\s*x/i',

            // Iframe injection
            '/<\s*iframe/i',

            // Expression/eval constructs
            '/expression\s*\(/i',
            '/\beval\s*\(/i',
            '/\bFunction\s*\(/i',
            '#\bsetTimeout\s*\(\s*["\'\/]#i',
            '#\bsetInterval\s*\(\s*["\'\/]#i',

            // Template injection
            '/\{\{.*?\}\}/s',
            '/\$\{.*?\}/s',

            // Object/embed/applet tags
            '/<\s*object[\s>]/i',
            '/<\s*embed[\s>]/i',
            '/<\s*applet[\s>]/i',

            // HTML entity-encoded script
            '/&#x0*3[cC];?\s*script/i',
            '/&#0*60;?\s*script/i',

            // URL-encoded XSS
            '/%3[cC]script/i',
            '/%3[cC]svg/i',
            '/%3[cC]img/i',

            // document.cookie / document.domain access
            '/document\s*\.\s*(cookie|domain|location|write)/i',
            '/window\s*\.\s*location/i',

            // Fetch/XMLHttpRequest in injection context
            '/\bnew\s+XMLHttpRequest/i',
            '/\bfetch\s*\(\s*["\']http/i',
        ];
    }

    /**
     * Path traversal patterns detecting attempts to access files
     * outside the web root.
     *
     * @return string[] Array of regex patterns.
     */
    public static function pathTraversalPatterns(): array
    {
        return [
            // Standard directory traversal
            '#\.\./#',
            '#\.\.\\\\#',

            // URL-encoded traversal
            '/%2e%2e%2f/i',
            '/%2e%2e\//i',
            '/\.\.%2f/i',
            '/%2e%2e%5c/i',

            // Double URL-encoded traversal
            '/%252e%252e%252f/i',
            '/%252e%252e%255c/i',

            // Null byte injection (for bypassing extension checks)
            '/%00/i',

            // Unix sensitive files
            '/\/etc\/passwd/i',
            '/\/etc\/shadow/i',
            '/\/proc\/self\/environ/i',
            '/\/proc\/self\/fd/i',
            '/\/proc\/self\/cmdline/i',

            // Windows paths
            '/[a-zA-Z]:\\\\/i',
            '/\\\\windows\\\\system32/i',
            '/\\\\winnt\\\\/i',
            '/\\\\boot\.ini/i',

            // PHP stream wrappers for file access
            '/php:\/\/filter/i',
            '/php:\/\/input/i',
            '/expect:\/\//i',
            '/zip:\/\//i',
            '/phar:\/\//i',
            '/compress\.zlib:\/\//i',

            // Data wrapper
            '/data:\/\/text\/plain/i',
        ];
    }

    /**
     * Server-Side Request Forgery (SSRF) patterns detecting attempts
     * to make the server connect to internal resources.
     *
     * @return string[] Array of regex patterns.
     */
    public static function ssrfPatterns(): array
    {
        return [
            // Loopback / localhost
            '/127\.0\.0\.\d+/i',
            '/localhost/i',
            '/0\.0\.0\.0/i',
            '/\[?::1\]?/',

            // Private IP ranges (RFC 1918)
            '/10\.\d{1,3}\.\d{1,3}\.\d{1,3}/',
            '/192\.168\.\d{1,3}\.\d{1,3}/',
            '/172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}/',

            // Link-local
            '/169\.254\.\d{1,3}\.\d{1,3}/',

            // Cloud metadata endpoints
            '/169\.254\.169\.254/',
            '/metadata\.google\.internal/i',
            '/metadata\.aws\.internal/i',
            '/100\.100\.100\.200/',

            // Dangerous protocols
            '/file:\/\//i',
            '/dict:\/\//i',
            '/gopher:\/\//i',
            '/sftp:\/\//i',
            '/ldap:\/\//i',
            '/tftp:\/\//i',

            // URL parameters that commonly carry SSRF payloads
            '/[?&](url|redirect|next|target|dest|return|goto|link|proxy|site|path)\s*=\s*https?:\/\//i',
            '/[?&](url|redirect|next|target|dest|return|goto|link|proxy|site|path)\s*=\s*(file|dict|gopher|ldap):\/\//i',

            // Hex/octal IP encoding tricks
            '/0x[0-9a-f]{8}/i',
            '/0[0-7]{9,}/i',

            // Shortened localhost variants
            '/http:\/\/0\//i',
            '/http:\/\/0x7f/i',
        ];
    }

    /**
     * User-Agent strings associated with known scanning tools,
     * vulnerability scanners, and exploit frameworks.
     *
     * @return string[] Array of regex patterns.
     */
    public static function suspiciousUserAgents(): array
    {
        return [
            // SQL injection tools
            '/sqlmap/i',
            '/havij/i',

            // Web vulnerability scanners
            '/nikto/i',
            '/nessus/i',
            '/openvas/i',
            '/acunetix/i',
            '/qualys/i',
            '/w3af/i',
            '/skipfish/i',
            '/arachni/i',
            '/vega\//i',
            '/appscan/i',
            '/webscarab/i',
            '/paros/i',
            '/owasp/i',

            // Network scanners
            '/nmap/i',
            '/masscan/i',
            '/zmap/i',
            '/zgrab/i',
            '/censys/i',

            // Directory brute-forcers
            '/dirbuster/i',
            '/gobuster/i',
            '/wfuzz/i',
            '/ffuf/i',
            '/feroxbuster/i',
            '/dirb\b/i',

            // Exploitation frameworks
            '/metasploit/i',
            '/burpsuite/i',
            '/burp\s*suite/i',

            // Nuclei scanner
            '/nuclei/i',

            // Security testing
            '/commix/i',
            '/hydra/i',
            '/medusa/i',
        ];
    }

    /**
     * Patterns for detecting fake SEO/search engine bots that claim
     * to be legitimate crawlers but are not.
     *
     * @return string[] Array of legitimate bot User-Agent patterns
     *                  (used to check if a claimed bot is genuine).
     */
    public static function fakeSeoBot(): array
    {
        return [
            // Legitimate bot UA patterns paired with expected reverse-DNS domains
            'Googlebot' => 'google.com',
            'Bingbot' => 'search.msn.com',
            'Slurp' => 'crawl.yahoo.net',
            'DuckDuckBot' => 'duckduckgo.com',
            'Baiduspider' => 'baidu.com',
            'YandexBot' => 'yandex.com',
            'facebookexternalhit' => 'facebook.com',
            'Twitterbot' => 'twitter.com',
        ];
    }

    /**
     * Sensitive file paths that should never be publicly accessible.
     *
     * @return string[] Array of regex patterns matching sensitive file paths.
     */
    public static function sensitiveFilePaths(): array
    {
        return [
            // Environment files
            '/\.env(\.|$)/i',
            '/\.env\.local/i',
            '/\.env\.production/i',
            '/\.env\.staging/i',
            '/\.env\.development/i',
            '/\.env\.backup/i',

            // Version control
            '/\/\.git(\/|$)/i',
            '/\/\.svn(\/|$)/i',
            '/\/\.hg(\/|$)/i',
            '/\/\.bzr(\/|$)/i',

            // Apache/Nginx config
            '/\.htaccess/i',
            '/\.htpasswd/i',

            // Editor/IDE files
            '/\/\.idea(\/|$)/i',
            '/\/\.vscode(\/|$)/i',
            '/\/\.project$/i',
            '/\.swp$/i',
            '/~$/i',

            // OS files
            '/\.DS_Store/i',
            '/Thumbs\.db/i',
            '/desktop\.ini/i',

            // Package management
            '/composer\.json$/i',
            '/composer\.lock$/i',
            '/package\.json$/i',
            '/package-lock\.json$/i',
            '/yarn\.lock$/i',
            '/Gemfile(\.lock)?$/i',
            '/requirements\.txt$/i',
            '/Pipfile(\.lock)?$/i',

            // Log files
            '/error[_-]?log/i',
            '/access[_-]?log/i',
            '/debug[_-]?log/i',
            '/\.log$/i',

            // Database dumps
            '/\.sql$/i',
            '/\.sqlite$/i',
            '/\.db$/i',
            '/dump\.(sql|gz|zip)/i',

            // PHP info / test files
            '/phpinfo\.php/i',
            '/info\.php$/i',
            '/test\.php$/i',
            '/i\.php$/i',

            // Admin panels
            '/phpmyadmin/i',
            '/adminer\.php/i',
            '/adminer/i',

            // Web config
            '/web\.config/i',
        ];
    }

    /**
     * Configuration file paths commonly targeted by attackers.
     *
     * @return string[] Array of path substrings to match.
     */
    public static function configFilePaths(): array
    {
        return [
            // WordPress
            'wp-config.php',
            'wp-config.bak',
            'wp-config.old',
            'wp-config.save',
            'wp-config.orig',
            'wp-config.txt',
            'wp-config.tmp',
            'wp-config.php~',
            'wp-config.php.bak',
            'wp-config.php.old',
            'wp-config.php.save',
            'wp-config.php.orig',
            'wp-config.php.swp',
            'wp-config.php.txt',

            // Drupal
            'sites/default/settings.php',
            'sites/default/settings.local.php',

            // Joomla
            'configuration.php',
            'configuration.php.bak',

            // Laravel/general
            '.env',
            '.env.local',
            '.env.production',
            '.env.staging',
            '.env.development',
            '.env.backup',
            '.env.old',
            '.env.save',

            // Generic config
            'config.php',
            'config.inc.php',
            'db.php',
            'database.php',
            'database.yml',
            'settings.php',
            'local.php',

            // Magento
            'local.xml',
            'app/etc/local.xml',
            'app/etc/env.php',

            // Symfony
            'parameters.yml',
            'parameters.yaml',
            'app/config/parameters.yml',

            // General
            'config.yml',
            'config.yaml',
            'config.json',
            'secrets.json',
            'credentials.json',
        ];
    }

    /**
     * Known vulnerable plugin/theme paths commonly exploited by attackers.
     *
     * @return string[] Array of regex patterns matching known exploit paths.
     */
    public static function pluginExploitPaths(): array
    {
        return [
            // WordPress - Revolution Slider (CVE-2014-9734)
            '/\/wp-content\/plugins\/revslider/i',

            // WordPress - WP File Manager (CVE-2020-25213)
            '/\/wp-content\/plugins\/wp-file-manager/i',

            // WordPress - Duplicator (CVE-2020-11738)
            '/\/wp-content\/plugins\/duplicator/i',
            '/\/dup-installer/i',

            // WordPress - Easy WP SMTP
            '/\/wp-content\/plugins\/easy-wp-smtp/i',

            // WordPress - Contact Form 7 exploit paths
            '/\/wp-content\/plugins\/contact-form-7\/readme\.txt/i',

            // WordPress - Direct PHP execution in uploads
            '/\/wp-content\/uploads\/.*\.php/i',

            // WordPress - Theme shell upload targets
            '/\/wp-content\/themes\/[^\/]+\/404\.php/i',

            // WordPress - TimThumb
            '/\/wp-content\/themes\/.*timthumb/i',
            '/\/wp-content\/plugins\/.*timthumb/i',

            // WordPress - Gravity Forms
            '/\/wp-content\/plugins\/gravityforms/i',

            // WordPress - WPScan/enumeration paths
            '/\/wp-content\/debug\.log/i',

            // Drupal - Drupalgeddon (CVE-2018-7600)
            '/\/user\/register\?.*element_parents.*ajax_form/i',
            '/\/user\/password\?.*[\[\]]/i',

            // Drupal - Drupalgeddon 2 (CVE-2019-6340)
            '/\/node\/\d+\?.*_format=hal_json/i',
            '/\/_format=hal_json/i',

            // Drupal - Module scanning
            '/\/sites\/all\/modules\//i',
            '/\/sites\/default\/files\//i',

            // Joomla - com_fabrik (RCE)
            '/\/components\/com_fabrik/i',

            // Joomla - com_fields (SQLi CVE-2017-8917)
            '/\/components\/com_fields/i',

            // Joomla - Libraries
            '/\/libraries\/joomla\/.*\.php/i',

            // Joomla - com_media
            '/\/components\/com_media\/helpers/i',

            // Generic CMS plugin scanning patterns
            '/\/wp-content\/plugins\/[^\/]+\/readme\.txt/i',
            '/\/wp-content\/plugins\/[^\/]+\/changelog\.txt/i',
        ];
    }

    /**
     * Dangerous XML-RPC methods commonly abused for attacks.
     *
     * @return string[] Array of dangerous method name strings.
     */
    public static function xmlRpcMethods(): array
    {
        return [
            'system.multicall',
            'system.listMethods',
            'system.getCapabilities',
            'pingback.ping',
            'pingback.extensions.getPingbacks',
            'wp.getUsersBlogs',
            'wp.getAuthors',
            'wp.getUsers',
            'wp.getOptions',
            'wp.setOptions',
            'wp.getPageList',
            'wp.editPage',
            'wp.deletePage',
            'wp.newPost',
            'wp.editPost',
            'wp.deletePost',
            'wp.uploadFile',
            'wp.getProfile',
            'metaWeblog.getUsersBlogs',
            'metaWeblog.newPost',
            'metaWeblog.editPost',
            'metaWeblog.getPost',
        ];
    }

    /**
     * Common usernames used in brute force and credential stuffing attacks.
     *
     * @return string[] Array of username strings (lowercase).
     */
    public static function commonUsernames(): array
    {
        return [
            'admin',
            'administrator',
            'root',
            'test',
            'user',
            'guest',
            'info',
            'support',
            'webmaster',
            'postmaster',
            'hostmaster',
            'manager',
            'sales',
            'contact',
            'office',
            'demo',
            'master',
            'backup',
            'operator',
            'superadmin',
            'sysadmin',
            'www',
            'web',
            'ftp',
            'mysql',
            'postgres',
            'oracle',
            'nagios',
            'staff',
            'service',
        ];
    }

    /**
     * Keywords commonly found in spam form submissions.
     *
     * @return string[] Array of regex patterns.
     */
    public static function spamKeywords(): array
    {
        return [
            '/\bviagra\b/i',
            '/\bcialis\b/i',
            '/\bcasino\b/i',
            '/\bpoker\b/i',
            '/\blottery\b/i',
            '/\bjackpot\b/i',
            '/\bcrypto\s*(currency|trading|invest)/i',
            '/\bbitcoin\s*(trading|invest|profit)/i',
            '/\bforex\s*(trading|signal|profit)/i',
            '/\bbinary\s*option/i',
            '/\bpayday\s*loan/i',
            '/\bcheap\s*(meds|medication|pills|drugs)/i',
            '/\bbuy\s*(followers|likes|views)/i',
            '/\bfree\s*(iphone|ipad|gift\s*card|money)/i',
            '/\b(make|earn)\s*\$?\d+.*?(day|hour|week|month)/i',
            '/\bwork\s*from\s*home.*?\$\d+/i',
            '/\bweight\s*loss\s*(pill|supplement|miracle)/i',
            '/\bsex(ual)?\s*(enhancement|pill|supplement)/i',
            '/\benlarge(ment)?\s*(pill|supplement)/i',
            '/\bpharmacy\s*online/i',
            '/\bdiet\s*(pill|supplement|miracle)/i',
            '/\bMLM\b/i',
            '/\bpyramid\s*scheme/i',
            '/\bnigerian?\s*prince/i',
            '/\binheritance\s*(fund|claim|million)/i',
            '/\b(click|visit)\s*(here|now|this\s*link)\b/i',
        ];
    }

    /**
     * Patterns matching known CVE exploit paths and payloads.
     *
     * @return string[] Array of regex patterns.
     */
    public static function cvePatterns(): array
    {
        return [
            // Log4Shell (CVE-2021-44228) and variants
            '/\$\{jndi:(ldap|rmi|dns|iiop|corba|nds|http|https):\/\//i',
            '/\$\{jndi:/i',
            '/\$\{\$\{(lower|upper):[jJ]/i',
            '/\$\{(env|sys|java|main):/i',

            // Spring4Shell (CVE-2022-22965)
            '/class\.module\.classLoader/i',
            '/class%2emodule%2eclassLoader/i',

            // ThinkPHP RCE
            '/index\.php\?s=\/Index\/.*\\\\think/i',
            '/invokefunction/i',

            // PHPUnit RCE (CVE-2017-9841)
            '/vendor\/phpunit\/phpunit\/src\/Util\/PHP\/eval-stdin\.php/i',

            // Apache Struts (CVE-2017-5638)
            '/%\{.*?\}/i',

            // Shellshock (CVE-2014-6271)
            '/\(\)\s*\{\s*:;\s*\}\s*;/i',

            // WordPress REST API user enumeration
            '/\/wp-json\/wp\/v2\/users/i',

            // vBulletin RCE (CVE-2019-16759)
            '/routestring=ajax/i',

            // Confluence (CVE-2021-26084)
            '/\/pages\/createpage-entervariables\.action/i',

            // Apache Tomcat ghostcat (CVE-2020-1938)
            '/\/WEB-INF\//i',
            '/\/META-INF\//i',

            // F5 BIG-IP (CVE-2020-5902)
            '/\/tmui\/login\.jsp/i',
            '/\/hsqldb/i',

            // Exchange ProxyShell/ProxyLogon
            '/\/autodiscover\/autodiscover\.json/i',
            '/\/mapi\/nspi/i',
            '/\/ecp\/.*\.js/i',

            // Atlassian Confluence OGNL (CVE-2022-26134)
            '/\$\{.*?Runtime.*?exec/i',
        ];
    }

    /**
     * Webshell and remote code execution indicator patterns.
     *
     * @return string[] Array of regex patterns.
     */
    public static function shellPatterns(): array
    {
        return [
            // Direct shell commands in parameters
            '/[?&](cmd|exec|command|execute|run|shell|system|passthru)\s*=/i',

            // PHP code execution functions
            '/\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(/i',

            // PHP backtick execution
            '/`[^`]*`/',

            // Common webshell signatures
            '/c99shell/i',
            '/r57shell/i',
            '/b374k/i',
            '/wso\s*shell/i',
            '/alfa\s*shell/i',
            '/weevely/i',
            '/phpspy/i',
            '/ani-?shell/i',

            // Base64-encoded PHP code
            '/base64_decode\s*\(\s*["\'][A-Za-z0-9+\/=]{20,}/i',

            // PHP code in various parameters
            '/\bphp\s*\/\/.*?(eval|exec|system|passthru)/i',

            // File write/upload indicators
            '/file_put_contents\s*\(/i',
            '/fwrite\s*\(/i',
            '/move_uploaded_file\s*\(/i',

            // Process execution
            '/proc_open\s*\(/i',
            '/pcntl_exec\s*\(/i',

            // Reverse shell indicators
            '/\/bin\/(bash|sh|zsh|csh|ksh)/i',
            '/nc\s+-[elp]/i',
            '/ncat\s/i',
            '/python.*?-c.*?(import|socket|subprocess)/i',
            '/perl.*?-e.*?(socket|exec)/i',
            '/ruby.*?-e.*?(socket|exec)/i',
        ];
    }

    /**
     * Common default passwords used in credential stuffing attacks.
     *
     * @return string[] Array of password strings.
     */
    public static function commonPasswords(): array
    {
        return [
            'admin',
            'password',
            '123456',
            '12345678',
            '123456789',
            '1234567890',
            'password1',
            'qwerty',
            'abc123',
            'letmein',
            'welcome',
            'monkey',
            'dragon',
            'master',
            'login',
            'princess',
            'football',
            'shadow',
            'sunshine',
            'trustno1',
            'iloveyou',
            'batman',
            'access',
            'hello',
            'charlie',
            'donald',
            '!@#$%^&*',
            'passw0rd',
            'P@ssw0rd',
            'P@ssword1',
            'admin123',
            'root',
            'toor',
            'pass',
            'test',
            'guest',
            'changeme',
            'default',
        ];
    }
}
