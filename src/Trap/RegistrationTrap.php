<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Trap;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Core\Response;
use ReportedIp\Honeypot\Profile\CmsProfile;

/**
 * User registration trap.
 *
 * Shows a fake registration form and accepts submissions with a
 * "check your email" confirmation, logging all registration attempts.
 */
class RegistrationTrap implements TrapInterface
{
    public function getName(): string
    {
        return 'registration';
    }

    public function handle(Request $request, Response $response, CmsProfile $profile): Response
    {
        foreach ($profile->getDefaultHeaders() as $name => $value) {
            $response->setHeader($name, $value);
        }

        $data = $profile->getTemplateData();
        $data['registration_success'] = false;
        $data['registration_error'] = '';

        if ($request->isPost()) {
            // Simulate processing delay
            usleep(random_int(200000, 600000));

            $data['registration_success'] = true;
            $data['registration_message'] = $this->getSuccessMessage($profile->getName());
        }

        $data['is_registration_page'] = true;

        // Use the login template with registration mode for WP
        $templatePath = __DIR__ . '/../../templates/' . $profile->getTemplatePath() . '/login.php';

        $response->setStatusCode(200);
        $response->setContentType('text/html; charset=UTF-8');
        $response->renderTemplate($templatePath, $data);

        return $response;
    }

    /**
     * Get a CMS-appropriate registration success message.
     */
    private function getSuccessMessage(string $cms): string
    {
        return match ($cms) {
            'wordpress' => 'Registration complete. Please check your email.',
            'drupal'    => 'A welcome message with further instructions has been sent to your email address.',
            'joomla'    => 'Your account has been created. An activation link has been sent to the email address you provided.',
            default     => 'Registration complete. Please check your email.',
        };
    }
}
