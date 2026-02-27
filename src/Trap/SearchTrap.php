<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Trap;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Core\Response;
use ReportedIp\Honeypot\Profile\CmsProfile;

/**
 * Search query trap.
 *
 * Returns fake search results and logs search terms, which often
 * contain SQL injection or XSS probes from attackers.
 */
class SearchTrap implements TrapInterface
{
    public function getName(): string
    {
        return 'search';
    }

    public function handle(Request $request, Response $response, CmsProfile $profile): Response
    {
        foreach ($profile->getDefaultHeaders() as $name => $value) {
            $response->setHeader($name, $value);
        }

        $queryParams = $request->getQueryParams();
        $searchTerm = $this->extractSearchTerm($queryParams, $profile->getName());

        $data = $profile->getTemplateData();
        $data['search_term'] = htmlspecialchars($searchTerm, ENT_QUOTES, 'UTF-8');
        $data['search_results'] = $this->getFakeResults($profile->getName());
        $data['is_search_page'] = true;

        $templatePath = __DIR__ . '/../../templates/' . $profile->getTemplatePath() . '/home.php';

        $response->setStatusCode(200);
        $response->setContentType('text/html; charset=UTF-8');
        $response->renderTemplate($templatePath, $data);

        return $response;
    }

    /**
     * Extract search term from query parameters using CMS-specific param names.
     */
    private function extractSearchTerm(array $params, string $cms): string
    {
        $field = match ($cms) {
            'wordpress' => 's',
            'drupal'    => 'keys',
            'joomla'    => 'searchword',
            default     => 's',
        };

        return (string) ($params[$field] ?? $params['q'] ?? $params['s'] ?? '');
    }

    /**
     * Generate fake search results.
     *
     * @return array<int, array{title: string, excerpt: string, url: string}>
     */
    private function getFakeResults(string $cms): array
    {
        return [
            [
                'title'   => 'Hello world!',
                'excerpt' => 'Welcome to our site. This is our first post. Edit or delete it, then start writing!',
                'url'     => '/hello-world/',
            ],
            [
                'title'   => 'Sample Page',
                'excerpt' => 'This is an example page. It is different from a blog post because it stays in one place.',
                'url'     => '/sample-page/',
            ],
            [
                'title'   => 'About Us',
                'excerpt' => 'Learn more about our company and what we do.',
                'url'     => '/about/',
            ],
        ];
    }
}
