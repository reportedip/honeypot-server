<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Trap;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Core\Response;
use ReportedIp\Honeypot\Profile\CmsProfile;

/**
 * Fake CMS admin dashboard trap.
 *
 * Shows a convincing admin interface to waste attacker time,
 * or redirects to login if the attacker has not "authenticated".
 */
class AdminTrap implements TrapInterface
{
    public function getName(): string
    {
        return 'admin';
    }

    public function handle(Request $request, Response $response, CmsProfile $profile): Response
    {
        foreach ($profile->getDefaultHeaders() as $name => $value) {
            $response->setHeader($name, $value);
        }

        // Check for a fake auth cookie to decide whether to show admin or redirect
        $cookies = $request->getHeader('Cookie') ?? '';
        $isAuthenticated = str_contains($cookies, 'wordpress_logged_in')
            || str_contains($cookies, 'SESS')
            || str_contains($cookies, 'joomla_user_state');

        if (!$isAuthenticated) {
            // Redirect to login page like the real CMS would
            $loginPath = $profile->getLoginPath();
            $redirectParam = match ($profile->getName()) {
                'wordpress' => '?redirect_to=' . urlencode($request->getPath()),
                'drupal'    => '?destination=' . urlencode(ltrim($request->getPath(), '/')),
                'joomla'    => '?return=' . base64_encode($request->getPath()),
                default     => '',
            };
            $response->redirect($loginPath . $redirectParam, 302);
            return $response;
        }

        $data = $profile->getTemplateData();
        $data['request_path'] = $request->getPath();
        $templatePath = __DIR__ . '/../../templates/' . $profile->getTemplatePath() . '/admin.php';

        $response->setStatusCode(200);
        $response->setContentType('text/html; charset=UTF-8');
        $response->setHeader('Cache-Control', 'no-cache, must-revalidate, max-age=0');
        $response->setHeader('X-Robots-Tag', 'noindex, nofollow');
        $response->renderTemplate($templatePath, $data);

        return $response;
    }
}
