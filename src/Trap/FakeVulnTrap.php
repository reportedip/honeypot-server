<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Trap;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Core\Response;
use ReportedIp\Honeypot\Profile\CmsProfile;

/**
 * Fake vulnerability response trap.
 *
 * Returns convincing fake vulnerable content for known vulnerability
 * and enumeration paths to lure and identify attackers.
 */
class FakeVulnTrap implements TrapInterface
{
    public function getName(): string
    {
        return 'fake_vuln';
    }

    public function handle(Request $request, Response $response, CmsProfile $profile): Response
    {
        foreach ($profile->getDefaultHeaders() as $name => $value) {
            $response->setHeader($name, $value);
        }

        $path = $request->getPath();

        return match ($profile->getName()) {
            'wordpress' => $this->handleWordPress($path, $request, $response, $profile),
            'drupal'    => $this->handleDrupal($path, $request, $response, $profile),
            'joomla'    => $this->handleJoomla($path, $request, $response, $profile),
            default     => $this->handleWordPress($path, $request, $response, $profile),
        };
    }

    /**
     * Handle WordPress vulnerability paths.
     */
    private function handleWordPress(
        string $path,
        Request $request,
        Response $response,
        CmsProfile $profile
    ): Response {
        // wp-config.php.bak - Fake config with dummy DB credentials
        if ($path === '/wp-config.php.bak') {
            $response->setStatusCode(200);
            $response->setContentType('application/octet-stream');
            $response->setHeader('Content-Disposition', 'attachment; filename="wp-config.php.bak"');
            $response->setBody($this->getFakeWpConfig());
            return $response;
        }

        // readme.html - WordPress readme showing an older "vulnerable" version
        if ($path === '/readme.html') {
            $response->setStatusCode(200);
            $response->setContentType('text/html; charset=UTF-8');
            $response->setBody($this->getFakeReadmeHtml());
            return $response;
        }

        // debug.log - Fake debug log with DB errors
        if ($path === '/wp-content/debug.log') {
            $response->setStatusCode(200);
            $response->setContentType('text/plain; charset=UTF-8');
            $response->setBody($this->getFakeDebugLog());
            return $response;
        }

        // /wp-json/wp/v2/users - Handled by RestApiTrap, but provide fallback
        if (str_starts_with($path, '/wp-json/wp/v2/users')) {
            $restApi = new RestApiTrap();
            return $restApi->handle($request, $response, $profile);
        }

        // ?author=1 - User enumeration redirect
        if (str_contains($path, '?author=') || str_contains($request->getUri(), 'author=')) {
            $response->redirect('/author/admin/', 301);
            return $response;
        }

        // /author/admin/ - Author page
        if (str_starts_with($path, '/author/')) {
            $data = $profile->getTemplateData();
            $data['author_name'] = 'admin';
            $data['is_author_page'] = true;
            $response->setStatusCode(200);
            $response->setContentType('text/html; charset=UTF-8');
            $response->renderTemplate(__DIR__ . '/../../templates/' . $profile->getTemplatePath() . '/home.php', $data);
            return $response;
        }

        // /wp-content/plugins/revslider/ - Fake directory listing
        if (str_starts_with($path, '/wp-content/plugins/revslider/')) {
            $response->setStatusCode(200);
            $response->setContentType('text/html; charset=UTF-8');
            $response->setBody($this->getFakeDirectoryListing($path));
            return $response;
        }

        // /wp-content/uploads/ - Fake directory listing
        if ($path === '/wp-content/uploads/' || str_starts_with($path, '/wp-content/uploads/')) {
            $response->setStatusCode(200);
            $response->setContentType('text/html; charset=UTF-8');
            $response->setBody($this->getFakeUploadsListing($path));
            return $response;
        }

        // /wp-includes/ - Fake forbidden
        if ($path === '/wp-includes' || str_starts_with($path, '/wp-includes/')) {
            $response->setStatusCode(403);
            $response->setContentType('text/html; charset=UTF-8');
            $response->setBody($this->getForbiddenPage());
            return $response;
        }

        // /wp-content/ and subdirectories - WordPress default blank index.php ("Silence is golden.")
        if ($path === '/wp-content' || $path === '/wp-content/' || str_starts_with($path, '/wp-content/')) {
            $response->setStatusCode(200);
            $response->setContentType('text/html; charset=UTF-8');
            $response->setBody('');
            return $response;
        }

        // Fallback: 404
        $notFound = new NotFoundTrap();
        return $notFound->handle($request, $response, $profile);
    }

    /**
     * Handle Drupal vulnerability paths.
     */
    private function handleDrupal(
        string $path,
        Request $request,
        Response $response,
        CmsProfile $profile
    ): Response {
        // CHANGELOG.txt - Shows Drupal 7.58 (Drupalgeddon vulnerable)
        if ($path === '/CHANGELOG.txt') {
            $response->setStatusCode(200);
            $response->setContentType('text/plain; charset=UTF-8');
            $response->setBody($this->getFakeDrupalChangelog());
            return $response;
        }

        // /sites/default/settings.php - Forbidden but leaks path info
        if ($path === '/sites/default/settings.php') {
            $response->setStatusCode(403);
            $response->setContentType('text/html; charset=UTF-8');
            $response->setBody($this->getDrupalForbidden());
            return $response;
        }

        // /user/1 - Fake admin user profile
        if (preg_match('#^/user/(\d+)$#', $path, $matches)) {
            $data = $profile->getTemplateData();
            $data['user_id'] = (int) $matches[1];
            $data['user_name'] = $matches[1] === '1' ? 'admin' : 'user' . $matches[1];
            $data['is_user_profile'] = true;
            $response->setStatusCode(200);
            $response->setContentType('text/html; charset=UTF-8');
            $response->renderTemplate(__DIR__ . '/../../templates/' . $profile->getTemplatePath() . '/home.php', $data);
            return $response;
        }

        // /update.php, /install.php, /core/install.php - Access denied
        if (in_array($path, ['/update.php', '/install.php', '/core/install.php'], true)) {
            $response->setStatusCode(403);
            $response->setContentType('text/html; charset=UTF-8');
            $response->setBody($this->getDrupalAccessDenied($path));
            return $response;
        }

        // /sites/all/modules/ - Directory listing
        if (str_starts_with($path, '/sites/all/modules/')) {
            $response->setStatusCode(403);
            $response->setContentType('text/html; charset=UTF-8');
            $response->setBody($this->getForbiddenPage());
            return $response;
        }

        $notFound = new NotFoundTrap();
        return $notFound->handle($request, $response, $profile);
    }

    /**
     * Handle Joomla vulnerability paths.
     */
    private function handleJoomla(
        string $path,
        Request $request,
        Response $response,
        CmsProfile $profile
    ): Response {
        // /administrator/manifests/files/joomla.xml - Version info
        if ($path === '/administrator/manifests/files/joomla.xml') {
            $response->setStatusCode(200);
            $response->setContentType('application/xml; charset=UTF-8');
            $response->setBody($this->getFakeJoomlaManifest());
            return $response;
        }

        // /configuration.php.bak - Fake Joomla config
        if ($path === '/configuration.php.bak') {
            $response->setStatusCode(200);
            $response->setContentType('application/octet-stream');
            $response->setHeader('Content-Disposition', 'attachment; filename="configuration.php.bak"');
            $response->setBody($this->getFakeJoomlaConfig());
            return $response;
        }

        // /components/com_fabrik/ or /components/com_fields/ - Directory listing
        if (str_starts_with($path, '/components/')) {
            $response->setStatusCode(200);
            $response->setContentType('text/html; charset=UTF-8');
            $response->setBody($this->getFakeDirectoryListing($path));
            return $response;
        }

        // /libraries/joomla/ - Directory listing
        if (str_starts_with($path, '/libraries/')) {
            $response->setStatusCode(403);
            $response->setContentType('text/html; charset=UTF-8');
            $response->setBody($this->getForbiddenPage());
            return $response;
        }

        // /plugins/ - Directory listing
        if (str_starts_with($path, '/plugins/')) {
            $response->setStatusCode(200);
            $response->setContentType('text/html; charset=UTF-8');
            $response->setBody($this->getFakeDirectoryListing($path));
            return $response;
        }

        $notFound = new NotFoundTrap();
        return $notFound->handle($request, $response, $profile);
    }

    // ---------------------------------------------------------------
    // WordPress fake content generators
    // ---------------------------------------------------------------

    private function getFakeWpConfig(): string
    {
        return <<<'PHP'
<?php
/**
 * The base configuration for WordPress
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress_db' );

/** Database username */
define( 'DB_USER', 'wpuser' );

/** Database password */
define( 'DB_PASSWORD', 'mySql_wp_2019' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The database collate type. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 */
define( 'AUTH_KEY',         'gK3!x$Ym9Qz@bN5wR8&pL2*cV7#jH4fT6^dA0sE1uW' );
define( 'SECURE_AUTH_KEY',  'mF8&hJ2@kL5!nP9#qR3$sT7%uV0^wX4*yA6+bC1dE' );
define( 'LOGGED_IN_KEY',    'zB3!cD5@eF7#gH9$iJ1%kL3^mN5*oP7+qR9sT1uV' );
define( 'NONCE_KEY',        'wX3!yZ5@aB7#cD9$eF1%gH3^iJ5*kL7+mN9oP1qR' );
define( 'AUTH_SALT',        'sT3!uV5@wX7#yZ9$aB1%cD3^eF5*gH7+iJ9kL1mN' );
define( 'SECURE_AUTH_SALT', 'oP3!qR5@sT7#uV9$wX1%yZ3^aB5*cD7+eF9gH1iJ' );
define( 'LOGGED_IN_SALT',   'kL3!mN5@oP7#qR9$sT1%uV3^wX5*yZ7+aB9cD1eF' );
define( 'NONCE_SALT',       'gH3!iJ5@kL7#mN9$oP1%qR3^sT5*uV7+wX9yZ1aB' );

/**#@-*/

/**
 * WordPress database table prefix.
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 */
define( 'WP_DEBUG', true );
define( 'WP_DEBUG_LOG', true );
define( 'WP_DEBUG_DISPLAY', false );

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
    define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
PHP;
    }

    private function getFakeReadmeHtml(): string
    {
        return <<<'HTML'
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>WordPress &rsaquo; ReadMe</title>
<style type="text/css">body{font-family:"Open Sans",sans-serif;font-size:14px;line-height:1.5;color:#444;margin:2em auto;max-width:700px;padding:0 20px}h1{color:#0073aa;font-size:36px;font-weight:400;margin-bottom:0}h1 img{margin-right:12px;vertical-align:middle}h2{font-size:20px;color:#23282d}a{color:#0073aa;text-decoration:none}a:hover{color:#00a0d2}</style>
</head>
<body>
<h1><img src="/wp-admin/images/wordpress-logo.png" alt="WordPress" width="140"> WordPress</h1>
<p>Semantic Personal Publishing Platform</p>
<h2>Version 6.4.2</h2>
<p>Welcome. WordPress is a very special project to me. Every developer and contributor adds something unique to the mix, and together we create something beautiful that I am proud to be a part of. Thousands of hours have gone into WordPress, and we are dedicated to making it better every day.</p>
<h2>Installation: Famous 5-minute install</h2>
<ol>
<li>Unzip the package in an empty directory and upload everything.</li>
<li>Open <code>wp-admin/install.php</code> in your browser.</li>
<li>Follow the instructions and set up your site.</li>
</ol>
<h2>System Requirements</h2>
<ul>
<li>PHP version 7.4 or greater.</li>
<li>MySQL version 5.7 or greater OR MariaDB version 10.4 or greater.</li>
</ul>
</body>
</html>
HTML;
    }

    private function getFakeDebugLog(): string
    {
        $dates = [];
        $base = time() - 86400;
        for ($i = 0; $i < 15; $i++) {
            $dates[] = gmdate('[d-M-Y H:i:s UTC]', $base + ($i * 3600));
        }

        return <<<LOG
{$dates[0]} PHP Warning:  mysqli_real_connect(): (HY000/1045): Access denied for user 'wpuser'@'localhost' (using password: YES) in /var/www/html/wp-includes/class-wpdb.php on line 1987
{$dates[1]} PHP Notice:  Trying to get property 'post_type' of non-object in /var/www/html/wp-includes/post.php on line 243
{$dates[2]} PHP Warning:  Cannot modify header information - headers already sent by (output started at /var/www/html/wp-content/plugins/revslider/includes/slider.class.php:47) in /var/www/html/wp-includes/pluggable.php on line 1435
{$dates[3]} PHP Fatal error:  Allowed memory size of 268435456 bytes exhausted (tried to allocate 4096 bytes) in /var/www/html/wp-includes/wp-db.php on line 2056
{$dates[4]} PHP Warning:  file_get_contents(/var/www/html/wp-content/uploads/2024/01/backup.sql): failed to open stream: No such file or directory in /var/www/html/wp-content/plugins/backup-plugin/backup.php on line 112
{$dates[5]} PHP Notice:  Undefined index: user_login in /var/www/html/wp-includes/user.php on line 237
{$dates[6]} PHP Warning:  Invalid argument supplied for foreach() in /var/www/html/wp-content/themes/flavor_flavor_flavor_flavor/functions.php on line 89
{$dates[7]} PHP Warning:  mysqli_real_connect(): (HY000/2002): Connection refused in /var/www/html/wp-includes/class-wpdb.php on line 1987
{$dates[8]} WordPress database error Table 'wordpress_db.wp_options' doesn't exist for query SELECT option_value FROM wp_options WHERE option_name = 'siteurl' LIMIT 1
{$dates[9]} PHP Notice:  Trying to access array offset on value of type bool in /var/www/html/wp-content/plugins/woocommerce/includes/class-wc-session-handler.php on line 73
{$dates[10]} PHP Warning:  call_user_func_array() expects parameter 1 to be a valid callback in /var/www/html/wp-includes/class-wp-hook.php on line 324
{$dates[11]} PHP Fatal error:  Uncaught Error: Class 'RevSliderFront' not found in /var/www/html/wp-content/plugins/revslider/revslider.php:75
{$dates[12]} PHP Warning:  session_start(): Cannot start session when headers already sent in /var/www/html/wp-content/plugins/contact-form-7/includes/controller.php on line 15
{$dates[13]} PHP Notice:  wp_enqueue_script was called incorrectly. Scripts and styles should not be registered or enqueued until the wp_enqueue_scripts hook. in /var/www/html/wp-includes/functions.php on line 5865
{$dates[14]} WordPress database error Got error 28 from storage engine for query SELECT * FROM wp_posts WHERE post_status = 'publish' ORDER BY post_date DESC LIMIT 10
LOG;
    }

    private function getFakeDirectoryListing(string $path): string
    {
        $escapedPath = htmlspecialchars($path, ENT_QUOTES, 'UTF-8');
        $date = gmdate('Y-M-d H:i');

        return <<<HTML
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
<head><title>Index of {$escapedPath}</title></head>
<body>
<h1>Index of {$escapedPath}</h1>
<pre>
<img src="/icons/blank.gif" alt="[ICO]"> <a href="?C=N;O=D">Name</a>                    <a href="?C=M;O=A">Last modified</a>      <a href="?C=S;O=A">Size</a>  <a href="?C=D;O=A">Description</a>
<hr>
<img src="/icons/back.gif" alt="[PARENTDIR]"> <a href="../">Parent Directory</a>                             -
<img src="/icons/folder.gif" alt="[DIR]"> <a href="css/">css/</a>                    {$date}    -
<img src="/icons/folder.gif" alt="[DIR]"> <a href="js/">js/</a>                     {$date}    -
<img src="/icons/folder.gif" alt="[DIR]"> <a href="includes/">includes/</a>               {$date}    -
<img src="/icons/text.gif" alt="[TXT]"> <a href="readme.txt">readme.txt</a>              {$date}  2.3K
<img src="/icons/unknown.gif" alt="[   ]"> <a href="index.php">index.php</a>               {$date}  1.1K
<hr>
</pre>
<address>Apache/2.4.58 (Ubuntu) Server at localhost Port 80</address>
</body>
</html>
HTML;
    }

    private function getFakeUploadsListing(string $path): string
    {
        $date = gmdate('Y-M-d H:i');

        return <<<HTML
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
<head><title>Index of /wp-content/uploads/</title></head>
<body>
<h1>Index of /wp-content/uploads/</h1>
<pre>
<img src="/icons/blank.gif" alt="[ICO]"> <a href="?C=N;O=D">Name</a>                    <a href="?C=M;O=A">Last modified</a>      <a href="?C=S;O=A">Size</a>  <a href="?C=D;O=A">Description</a>
<hr>
<img src="/icons/back.gif" alt="[PARENTDIR]"> <a href="../">Parent Directory</a>                             -
<img src="/icons/folder.gif" alt="[DIR]"> <a href="2024/">2024/</a>                   {$date}    -
<img src="/icons/folder.gif" alt="[DIR]"> <a href="2023/">2023/</a>                   {$date}    -
<img src="/icons/folder.gif" alt="[DIR]"> <a href="woocommerce_uploads/">woocommerce_uploads/</a>    {$date}    -
<hr>
</pre>
<address>Apache/2.4.58 (Ubuntu) Server at localhost Port 80</address>
</body>
</html>
HTML;
    }

    private function getForbiddenPage(): string
    {
        return <<<'HTML'
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.58 (Ubuntu) Server at localhost Port 80</address>
</body></html>
HTML;
    }

    // ---------------------------------------------------------------
    // Drupal fake content generators
    // ---------------------------------------------------------------

    private function getFakeDrupalChangelog(): string
    {
        return <<<'TXT'

Drupal 7.58, 2018-03-28
------------------------
- Fixed security issues (multiple vulnerabilities). See SA-CORE-2018-002.

Drupal 7.57, 2018-02-21
------------------------
- Fixed security issues (multiple vulnerabilities). See SA-CORE-2018-001.

Drupal 7.56, 2017-06-21
------------------------
- Fixed security issues (access bypass). See SA-CORE-2017-003.

Drupal 7.54, 2017-02-01
------------------------
- Fixed security issues (multiple vulnerabilities). See SA-CORE-2017-001.

Drupal 7.53, 2016-12-07
------------------------
- Fixed a regression introduced in Drupal 7.52.

Drupal 7.52, 2016-11-16
------------------------
- Fixed security issues (multiple vulnerabilities). See SA-CORE-2016-005.

Drupal 7.51, 2016-10-05
------------------------
- Fixed a regression that caused issues with certain contributed modules.
TXT;
    }

    private function getDrupalForbidden(): string
    {
        return <<<'HTML'
<!DOCTYPE html>
<html>
<head><title>403 Forbidden</title></head>
<body>
<h1>Forbidden</h1>
<p>You don't have permission to access /sites/default/settings.php on this server.</p>
<p>Additionally, a 403 Forbidden error was encountered while trying to use an ErrorDocument to handle the request.</p>
<hr>
<address>Apache/2.4.58 (Ubuntu) Server at localhost Port 80</address>
</body>
</html>
HTML;
    }

    private function getDrupalAccessDenied(string $path): string
    {
        $escaped = htmlspecialchars($path, ENT_QUOTES, 'UTF-8');

        return <<<HTML
<!DOCTYPE html>
<html>
<head>
<title>Access denied | Drupal</title>
<style>body{font-family:Georgia,"Times New Roman",serif;color:#494949;background:#fff;margin:2em}h1{font-size:1.3em;font-weight:normal;margin:0 0 .5em}</style>
</head>
<body>
<h1>Access denied</h1>
<p>You are not authorized to access this page.</p>
<p>If you are already logged in, please contact the site administrator.</p>
<hr>
<small>{$escaped} - Drupal</small>
</body>
</html>
HTML;
    }

    // ---------------------------------------------------------------
    // Joomla fake content generators
    // ---------------------------------------------------------------

    private function getFakeJoomlaManifest(): string
    {
        return <<<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<extension version="4.4" type="file" method="upgrade">
    <name>files_joomla</name>
    <author>Joomla! Project</author>
    <copyright>(C) 2005 - 2024 Open Source Matters. All rights reserved</copyright>
    <license>GNU General Public License version 2 or later; see LICENSE.txt</license>
    <authorEmail>admin@joomla.org</authorEmail>
    <authorUrl>www.joomla.org</authorUrl>
    <version>4.4.2</version>
    <creationDate>2024-01</creationDate>
    <description>FILES_JOOMLA_XML_DESCRIPTION</description>
    <scriptfile>administrator/components/com_admin/script.php</scriptfile>
    <update>
        <schemas>
            <schemapath type="mysql">administrator/components/com_admin/sql/updates/mysql</schemapath>
            <schemapath type="postgresql">administrator/components/com_admin/sql/updates/postgresql</schemapath>
        </schemas>
    </update>
    <fileset>
        <files>
            <folder>administrator</folder>
            <folder>api</folder>
            <folder>cache</folder>
            <folder>cli</folder>
            <folder>components</folder>
            <folder>images</folder>
            <folder>includes</folder>
            <folder>language</folder>
            <folder>layouts</folder>
            <folder>libraries</folder>
            <folder>media</folder>
            <folder>modules</folder>
            <folder>plugins</folder>
            <folder>templates</folder>
            <folder>tmp</folder>
            <file>htaccess.txt</file>
            <file>web.config.txt</file>
            <file>LICENSE.txt</file>
            <file>README.txt</file>
            <file>index.php</file>
        </files>
    </fileset>
</extension>
XML;
    }

    private function getFakeJoomlaConfig(): string
    {
        return <<<'PHP'
<?php
class JConfig {
    public $offline = false;
    public $offline_message = 'This site is down for maintenance.<br>Please check back again soon.';
    public $display_offline_message = 1;
    public $offline_image = '';
    public $sitename = 'My Joomla Site';
    public $editor = 'tinymce';
    public $captcha = '0';
    public $list_limit = 20;
    public $access = 1;
    public $debug = false;
    public $debug_lang = false;
    public $debug_lang_const = true;
    public $dbtype = 'mysqli';
    public $host = 'localhost';
    public $user = 'joomla_dbuser';
    public $password = 'J00ml@_Pr0d#2024!';
    public $db = 'joomla_production';
    public $dbprefix = 'jml_';
    public $dbencryption = 0;
    public $dbsslverifyservercert = false;
    public $dbsslkey = '';
    public $dbsslcert = '';
    public $dbsslca = '';
    public $dbsslcipher = '';
    public $force_ssl = 0;
    public $live_site = '';
    public $secret = 'aK4x8mZnQ9vBw3yR7cE2fH5jL0pS6tU';
    public $gzip = false;
    public $error_reporting = 'default';
    public $helpurl = 'https://help.joomla.org/proxy?keyref=Help{major}{minor}:{keyref}&lang={langcode}';
    public $offset = 'UTC';
    public $mailer = 'mail';
    public $mailfrom = 'admin@example.com';
    public $fromname = 'My Joomla Site';
    public $sendmail = '/usr/sbin/sendmail';
    public $smtpauth = false;
    public $smtpuser = '';
    public $smtppass = '';
    public $smtphost = 'localhost';
    public $smtpsecure = 'none';
    public $smtpport = 25;
    public $caching = 0;
    public $cache_handler = 'file';
    public $cachetime = 15;
    public $cache_platformprefix = false;
    public $MetaDesc = '';
    public $MetaAuthor = true;
    public $MetaVersion = false;
    public $robots = '';
    public $sef = true;
    public $sef_rewrite = false;
    public $sef_suffix = false;
    public $unicodeslugs = false;
    public $feed_limit = 10;
    public $feed_email = 'none';
    public $log_path = '/var/www/html/administrator/logs';
    public $tmp_path = '/var/www/html/tmp';
    public $lifetime = 15;
    public $session_handler = 'database';
    public $shared_session = false;
    public $session_metadata = true;
}
PHP;
    }
}
