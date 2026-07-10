<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Trap;

use ReportedIp\Honeypot\Content\ContentRepository;
use ReportedIp\Honeypot\Content\ContentUrlGenerator;
use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Core\Response;
use ReportedIp\Honeypot\Detection\SpiderTrap;
use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Profile\CmsProfile;

/**
 * Serves the fake CMS homepage with realistic-looking content.
 */
class HomeTrap implements TrapInterface, DatabaseAwareInterface
{
    private ?Database $db = null;

    public function getName(): string
    {
        return 'home';
    }

    public function setDatabase(Database $db): void
    {
        $this->db = $db;
    }

    public function handle(Request $request, Response $response, CmsProfile $profile): Response
    {
        // Apply CMS-specific default headers
        foreach ($profile->getDefaultHeaders() as $name => $value) {
            $response->setHeader($name, $value);
        }

        $templatePath = __DIR__ . '/../../templates/' . $profile->getTemplatePath() . '/home.php';
        $data = $profile->getTemplateData();
        $data['request_uri'] = $request->getUri();

        // Load generated posts if available
        if ($this->db !== null) {
            try {
                $repo = new ContentRepository($this->db);
                $posts = $repo->getPublished($profile->getName(), 10);
                foreach ($posts as &$post) {
                    $post['url'] = ContentUrlGenerator::getPostUrl($post);
                }
                unset($post);
                $data['generated_posts'] = $posts;
            } catch (\Throwable $e) {
                $data['generated_posts'] = [];
            }
        }

        $response->setStatusCode(200);
        $response->setContentType('text/html; charset=UTF-8');
        $response->renderTemplate($templatePath, $data);

        $this->injectHiddenBaitLink($response);

        return $response;
    }

    /**
     * Embed a hidden link to the spider-trap bait path. A human never sees it;
     * a scraper that follows every link walks straight into SpiderTrapAnalyzer.
     */
    private function injectHiddenBaitLink(Response $response): void
    {
        $link = '<a href="' . SpiderTrap::hiddenPath()
            . '" style="position:absolute;left:-9999px" aria-hidden="true" rel="nofollow">Member Area</a>';

        $body = $response->getBody();
        if (stripos($body, '</body>') !== false) {
            $body = preg_replace('#</body>#i', $link . '</body>', $body, 1) ?? $body;
        } else {
            $body .= $link;
        }
        $response->setBody($body);
    }
}
