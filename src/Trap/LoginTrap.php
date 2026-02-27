<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Trap;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Core\Response;
use ReportedIp\Honeypot\Profile\CmsProfile;

/**
 * Fake CMS login page trap.
 *
 * GET  - renders the login form with proper field names for each CMS.
 * POST - accepts any credentials, shows username-specific error messages
 *        (emulating real WordPress username enumeration), and adds a
 *        random delay to simulate real authentication.
 */
class LoginTrap implements TrapInterface
{
    /** Usernames that the honeypot pretends exist (triggers "incorrect password"). */
    private const KNOWN_USERNAMES = ['admin', 'editor', 'administrator', 'webmaster'];

    public function getName(): string
    {
        return 'login';
    }

    public function handle(Request $request, Response $response, CmsProfile $profile): Response
    {
        foreach ($profile->getDefaultHeaders() as $name => $value) {
            $response->setHeader($name, $value);
        }

        // WordPress sets a test cookie on the login page
        if ($profile->getName() === 'wordpress') {
            $response->setHeader('Set-Cookie', 'wordpress_test_cookie=WP+Cookie+check; path=/; HttpOnly');
        }

        // Handle ?action=lostpassword for WordPress
        if ($profile->getName() === 'wordpress' && $this->isLostPasswordAction($request)) {
            return $this->handleLostPassword($request, $response, $profile);
        }

        $data = $profile->getTemplateData();
        $data['error'] = '';
        $data['username_value'] = '';

        if ($request->isPost()) {
            // Simulate authentication delay (100-500ms)
            usleep(random_int(100000, 500000));

            $postData = $request->getPostData();
            $username = $this->extractUsername($postData, $profile->getName());
            $data['error'] = $this->getErrorMessage($profile->getName(), $username);
            $data['username_value'] = $username;
        }

        $templatePath = __DIR__ . '/../../templates/' . $profile->getTemplatePath() . '/login.php';

        $response->setStatusCode(200);
        $response->setContentType('text/html; charset=UTF-8');
        $response->renderTemplate($templatePath, $data);

        return $response;
    }

    /**
     * Check if the request is for the lost-password action.
     */
    private function isLostPasswordAction(Request $request): bool
    {
        $action = $request->getQueryParam('action');
        return $action === 'lostpassword';
    }

    /**
     * Render a fake password-reset form.
     */
    private function handleLostPassword(Request $request, Response $response, CmsProfile $profile): Response
    {
        $data = $profile->getTemplateData();
        $data['error'] = '';
        $data['username_value'] = '';

        if ($request->isPost()) {
            usleep(random_int(100000, 300000));
        }

        $siteUrl = htmlspecialchars($data['site_url'] ?? '', ENT_QUOTES, 'UTF-8');
        $siteName = htmlspecialchars($data['site_name'] ?? 'My WordPress Site', ENT_QUOTES, 'UTF-8');

        $html = <<<HTML
<!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="max-image-preview:large, noindex, noarchive, nofollow">
<title>{$siteName} &rsaquo; Lost Password</title>
<style type="text/css">
*{box-sizing:border-box}
body{background:#f0f0f1;min-width:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif;font-size:13px;line-height:1.4;color:#3c434a}
a{color:#2271b1;text-decoration:none}a:hover{color:#135e96}
#login{width:320px;padding:5% 0 0;margin:auto}
#login h1{text-align:center;margin-bottom:24px}
#login h1 a{display:inline-block;background-color:#3858e9;width:84px;height:84px;border-radius:50%;text-indent:-9999px;overflow:hidden;outline:0}
.login form{margin-top:20px;padding:26px 24px 34px;background:#fff;border:1px solid #c3c4c7;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
.login label{font-size:14px;line-height:1.5;display:block;margin-bottom:3px}
.login input[type="text"]{font-size:24px;width:100%;padding:3px;margin:2px 6px 16px 0;border:1px solid #8c8f94;border-radius:4px;background:#fff;color:#2c3338;line-height:1.33}
.login .message{border-left:4px solid #72aee6;padding:12px;margin-bottom:16px;background:#fff;box-shadow:0 1px 1px rgba(0,0,0,.04)}
.submit .button-primary{float:right;padding:0 12px;min-height:32px;background:#2271b1;border-color:#2271b1;color:#fff;font-size:13px;line-height:2.15;border-radius:3px;border:1px solid;cursor:pointer}
#nav,#backtoblog{font-size:13px;padding:0 24px;margin:16px 0}
#nav a,#backtoblog a{color:#50575e}
.clear{clear:both}
</style>
</head>
<body class="login wp-core-ui">
<div id="login">
<h1><a href="https://wordpress.org/" title="Powered by WordPress">{$siteName}</a></h1>
<p class="message">Please enter your username or email address. You will receive an email message with instructions on how to reset your password.</p>
<form name="lostpasswordform" id="lostpasswordform" action="{$siteUrl}/wp-login.php?action=lostpassword" method="post">
<p>
<label for="user_login">Username or Email Address</label>
<input type="text" name="user_login" id="user_login" autocapitalize="none" autocomplete="username" value="" size="20">
</p>
<input type="hidden" name="redirect_to" value="">
<p class="submit">
<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Get New Password">
</p>
</form>
<p id="nav">
<a href="{$siteUrl}/wp-login.php">Log in</a> |
<a href="{$siteUrl}/wp-login.php?action=register">Register</a>
</p>
<p id="backtoblog"><a href="{$siteUrl}/">&larr; Go to {$siteName}</a></p>
</div>
</body>
</html>
HTML;

        $response->setStatusCode(200);
        $response->setContentType('text/html; charset=UTF-8');
        $response->setBody($html);

        return $response;
    }

    /**
     * Get a CMS-appropriate login error message.
     *
     * For WordPress, this emulates real username enumeration behaviour:
     * known usernames get "incorrect password", unknown get "invalid username".
     */
    private function getErrorMessage(string $cms, string $username = ''): string
    {
        if ($cms === 'wordpress') {
            $lowerUsername = strtolower(trim($username));
            if ($lowerUsername !== '' && in_array($lowerUsername, self::KNOWN_USERNAMES, true)) {
                return '<strong>Error:</strong> The password you entered for the username <strong>'
                    . htmlspecialchars($username, ENT_QUOTES, 'UTF-8')
                    . '</strong> is incorrect. <a href="/wp-login.php?action=lostpassword">Lost your password?</a>';
            }
            return '<strong>Error:</strong> The username <strong>'
                . htmlspecialchars($username, ENT_QUOTES, 'UTF-8')
                . '</strong> is not registered on this site. If you are unsure of your username, try your email address instead.';
        }

        return match ($cms) {
            'drupal'  => 'Unrecognized username or password. <a href="/user/password">Have you forgotten your password?</a>',
            'joomla'  => 'Username and password do not match or you do not have an account yet.',
            default   => 'Invalid credentials.',
        };
    }

    /**
     * Extract the submitted username using CMS-specific field names.
     */
    private function extractUsername(array $postData, string $cms): string
    {
        $field = match ($cms) {
            'wordpress' => 'log',
            'drupal'    => 'name',
            'joomla'    => 'username',
            default     => 'username',
        };

        return (string) ($postData[$field] ?? '');
    }
}
