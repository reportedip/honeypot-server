<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Trap;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Core\Response;
use ReportedIp\Honeypot\Profile\CmsProfile;

/**
 * CMS-appropriate 404 page trap.
 *
 * Returns a realistic 404 error page styled for the active CMS profile.
 */
class NotFoundTrap implements TrapInterface
{
    public function getName(): string
    {
        return 'not_found';
    }

    public function handle(Request $request, Response $response, CmsProfile $profile): Response
    {
        foreach ($profile->getDefaultHeaders() as $name => $value) {
            $response->setHeader($name, $value);
        }

        $data = $profile->getTemplateData();
        $data['request_path'] = htmlspecialchars($request->getPath(), ENT_QUOTES, 'UTF-8');

        $templatePath = __DIR__ . '/../../templates/' . $profile->getTemplatePath() . '/404.php';

        $response->setStatusCode(404);
        $response->setContentType('text/html; charset=UTF-8');
        $response->renderTemplate($templatePath, $data);

        return $response;
    }
}
