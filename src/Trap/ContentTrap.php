<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Trap;

use ReportedIp\Honeypot\Content\ContentRepository;
use ReportedIp\Honeypot\Content\ContentUrlGenerator;
use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Core\Response;
use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Profile\CmsProfile;

/**
 * Serves AI-generated content pages with CMS-specific templates.
 */
final class ContentTrap implements TrapInterface, DatabaseAwareInterface
{
    private ?Database $db = null;

    public function getName(): string
    {
        return 'content';
    }

    public function setDatabase(Database $db): void
    {
        $this->db = $db;
    }

    public function handle(Request $request, Response $response, CmsProfile $profile): Response
    {
        if ($this->db === null) {
            return (new NotFoundTrap())->handle($request, $response, $profile);
        }

        $repo = new ContentRepository($this->db);
        $path = $request->getPath();
        $profileName = $profile->getName();
        $post = null;

        // Try to find content by slug
        $slug = ContentUrlGenerator::extractSlug($path, $profileName);
        if ($slug !== null) {
            $post = $repo->getBySlug($profileName, $slug);
        }

        // Try to find by ID (Drupal /node/ID)
        if ($post === null) {
            $id = ContentUrlGenerator::extractId($path, $profileName);
            if ($id !== null) {
                $post = $repo->getById($id);
                // Ensure it belongs to the correct profile
                if ($post !== null && $post['cms_profile'] !== $profileName) {
                    $post = null;
                }
            }
        }

        if ($post === null) {
            return (new NotFoundTrap())->handle($request, $response, $profile);
        }

        // Add URL to post data
        $post['url'] = ContentUrlGenerator::getPostUrl($post);

        // Get recent posts for sidebar
        $recentPosts = $repo->getPublished($profileName, 5);
        foreach ($recentPosts as &$rp) {
            $rp['url'] = ContentUrlGenerator::getPostUrl($rp);
        }
        unset($rp);

        // Apply CMS-specific default headers
        foreach ($profile->getDefaultHeaders() as $name => $value) {
            $response->setHeader($name, $value);
        }

        // Allow indexing of content pages
        $response->setHeader('X-Robots-Tag', 'index, follow');

        $templatePath = __DIR__ . '/../../templates/' . $profile->getTemplatePath() . '/content.php';
        $data = array_merge($profile->getTemplateData(), [
            'post'         => $post,
            'recent_posts' => $recentPosts,
            'request_uri'  => $request->getUri(),
        ]);

        $response->setStatusCode(200);
        $response->setContentType('text/html; charset=UTF-8');

        if (file_exists($templatePath)) {
            $response->renderTemplate($templatePath, $data);
        } else {
            // Fallback: basic HTML rendering
            $title = htmlspecialchars($post['title'] ?? '', ENT_QUOTES, 'UTF-8');
            $content = $post['content'] ?? '';
            $response->setBody("<!DOCTYPE html><html><head><title>{$title}</title></head><body><h1>{$title}</h1>{$content}</body></html>");
        }

        return $response;
    }
}
