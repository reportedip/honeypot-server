<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Trap;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Core\Response;
use ReportedIp\Honeypot\Profile\CmsProfile;

/**
 * Comment submission trap.
 *
 * Accepts spam comments, shows a "comment awaiting moderation" message,
 * and logs all submitted data for analysis.
 */
class CommentTrap implements TrapInterface
{
    public function getName(): string
    {
        return 'comment';
    }

    public function handle(Request $request, Response $response, CmsProfile $profile): Response
    {
        foreach ($profile->getDefaultHeaders() as $name => $value) {
            $response->setHeader($name, $value);
        }

        if (!$request->isPost()) {
            // GET requests to comment endpoints redirect to home
            $response->redirect('/', 302);
            return $response;
        }

        // Real WordPress does a 302 redirect after comment submission
        $commentId = random_int(100, 9999);
        $redirectUrl = '/?p=1&comment_approved=0#comment-' . $commentId;
        $response->redirect($redirectUrl, 302);

        return $response;
    }

    /**
     * Get a CMS-appropriate comment moderation message.
     */
    private function getSuccessMessage(string $cms): string
    {
        return match ($cms) {
            'wordpress' => 'Your comment is awaiting moderation. This is a preview; your comment will be visible after it has been approved.',
            'drupal'    => 'Your comment has been queued for review by site administrators and will be published after approval.',
            'joomla'    => 'Your comment has been submitted and is pending approval.',
            default     => 'Your comment has been submitted and is awaiting moderation.',
        };
    }
}
