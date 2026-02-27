<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Trap;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Core\Response;
use ReportedIp\Honeypot\Profile\CmsProfile;

/**
 * Contact form submission trap.
 *
 * Accepts all form data, shows a thank-you message, and logs everything.
 */
class ContactFormTrap implements TrapInterface
{
    public function getName(): string
    {
        return 'contact';
    }

    public function handle(Request $request, Response $response, CmsProfile $profile): Response
    {
        foreach ($profile->getDefaultHeaders() as $name => $value) {
            $response->setHeader($name, $value);
        }

        $data = $profile->getTemplateData();

        if ($request->isPost()) {
            $data['contact_success'] = true;
            $data['contact_message'] = $this->getThankYouMessage($profile->getName());
        } else {
            $data['contact_success'] = false;
            $data['contact_message'] = '';
        }

        $data['show_contact_form'] = !$request->isPost();

        $templatePath = __DIR__ . '/../../templates/' . $profile->getTemplatePath() . '/home.php';
        $data['is_contact_page'] = true;

        $response->setStatusCode(200);
        $response->setContentType('text/html; charset=UTF-8');
        $response->renderTemplate($templatePath, $data);

        return $response;
    }

    /**
     * Get a CMS-appropriate thank-you message.
     */
    private function getThankYouMessage(string $cms): string
    {
        return match ($cms) {
            'wordpress' => 'Thank you for your message. It has been sent.',
            'drupal'    => 'Your message has been sent.',
            'joomla'    => 'Your message has been successfully sent. Thank you.',
            default     => 'Thank you, your message has been sent.',
        };
    }
}
