<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Trap;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Core\Response;
use ReportedIp\Honeypot\Profile\CmsProfile;

/**
 * REST API endpoint trap.
 *
 * Handles /wp-json/ (WordPress), /jsonapi/ (Drupal), and /api/ (Joomla)
 * with convincing JSON responses including fake user enumeration data.
 */
class RestApiTrap implements TrapInterface
{
    public function getName(): string
    {
        return 'rest_api';
    }

    public function handle(Request $request, Response $response, CmsProfile $profile): Response
    {
        foreach ($profile->getDefaultHeaders() as $name => $value) {
            $response->setHeader($name, $value);
        }

        $response->setContentType('application/json; charset=UTF-8');
        $response->setHeader('X-Robots-Tag', 'noindex');
        $response->setHeader('Access-Control-Allow-Headers',
            'Authorization, Content-Type');

        $path = $request->getPath();

        return match ($profile->getName()) {
            'wordpress' => $this->handleWordPress($path, $request, $response, $profile),
            'drupal'    => $this->handleDrupal($path, $request, $response, $profile),
            'joomla'    => $this->handleJoomla($path, $request, $response, $profile),
            default     => $this->handleWordPress($path, $request, $response, $profile),
        };
    }

    /**
     * Handle WordPress REST API routes.
     */
    private function handleWordPress(
        string $path,
        Request $request,
        Response $response,
        CmsProfile $profile
    ): Response {
        $data = $profile->getTemplateData();
        $siteUrl = $data['site_url'] ?: '';

        // /wp-json/wp/v2/users - Fake user enumeration (the honeypot lure)
        if (str_starts_with($path, '/wp-json/wp/v2/users')) {
            $response->json([
                [
                    'id'          => 1,
                    'name'        => 'admin',
                    'url'         => $siteUrl,
                    'description' => '',
                    'link'        => $siteUrl . '/author/admin/',
                    'slug'        => 'admin',
                    'avatar_urls' => [
                        '24'  => 'https://secure.gravatar.com/avatar/?s=24&d=mm&r=g',
                        '48'  => 'https://secure.gravatar.com/avatar/?s=48&d=mm&r=g',
                        '96'  => 'https://secure.gravatar.com/avatar/?s=96&d=mm&r=g',
                    ],
                    'meta'  => [],
                    '_links' => [
                        'self'       => [['href' => $siteUrl . '/wp-json/wp/v2/users/1']],
                        'collection' => [['href' => $siteUrl . '/wp-json/wp/v2/users']],
                    ],
                ],
                [
                    'id'          => 2,
                    'name'        => 'editor',
                    'url'         => '',
                    'description' => '',
                    'link'        => $siteUrl . '/author/editor/',
                    'slug'        => 'editor',
                    'avatar_urls' => [
                        '24'  => 'https://secure.gravatar.com/avatar/?s=24&d=mm&r=g',
                        '48'  => 'https://secure.gravatar.com/avatar/?s=48&d=mm&r=g',
                        '96'  => 'https://secure.gravatar.com/avatar/?s=96&d=mm&r=g',
                    ],
                    'meta'  => [],
                    '_links' => [
                        'self'       => [['href' => $siteUrl . '/wp-json/wp/v2/users/2']],
                        'collection' => [['href' => $siteUrl . '/wp-json/wp/v2/users']],
                    ],
                ],
            ]);
            return $response;
        }

        // /wp-json/wp/v2/posts - Fake posts
        if (str_starts_with($path, '/wp-json/wp/v2/posts')) {
            $lang = $data['content_language'] ?? 'en';
            $isGerman = ($lang === 'de');
            $posts = $isGerman ? [
                ['id' => 5, 'slug' => 'responsives-webdesign-2024', 'date' => '2024-09-12T10:30:00', 'title' => 'Warum responsives Webdesign 2024 wichtiger denn je ist', 'excerpt' => 'Mobile Endger&auml;te machen mittlerweile &uuml;ber 60% des weltweiten Web-Traffics aus.', 'author' => 1, 'cat' => 1, 'month' => '09'],
                ['id' => 4, 'slug' => 'wordpress-sicherheitstipps', 'date' => '2024-08-23T14:15:00', 'title' => '5 h&auml;ufige Sicherheitsl&uuml;cken in WordPress und wie Sie sich sch&uuml;tzen', 'excerpt' => 'WordPress betreibt &uuml;ber 40% aller Websites weltweit.', 'author' => 1, 'cat' => 2, 'month' => '08'],
                ['id' => 3, 'slug' => 'partnerschaft-cloudsecure', 'date' => '2024-07-05T09:00:00', 'title' => 'Neue Partnerschaft mit CloudSecure f&uuml;r erweiterten DDoS-Schutz', 'excerpt' => 'Wir freuen uns, unsere neue Partnerschaft mit CloudSecure bekannt zu geben.', 'author' => 2, 'cat' => 3, 'month' => '07'],
                ['id' => 2, 'slug' => 'seo-grundlagen-meta-tags', 'date' => '2024-06-18T11:45:00', 'title' => 'SEO-Grundlagen: Meta-Tags und strukturierte Daten richtig einsetzen', 'excerpt' => 'Suchmaschinenoptimierung beginnt bei den Grundlagen.', 'author' => 1, 'cat' => 4, 'month' => '06'],
                ['id' => 1, 'slug' => 'sommeraktion-website-analyse', 'date' => '2024-05-02T08:30:00', 'title' => 'Sommeraktion: Kostenlose Website-Analyse f&uuml;r Neukunden', 'excerpt' => 'Nutzen Sie unsere kostenlose Website-Analyse.', 'author' => 2, 'cat' => 5, 'month' => '05'],
            ] : [
                ['id' => 5, 'slug' => 'responsive-web-design-2024', 'date' => '2024-09-12T10:30:00', 'title' => 'Why Responsive Web Design Matters More Than Ever in 2024', 'excerpt' => 'Mobile devices now account for over 60% of global web traffic.', 'author' => 1, 'cat' => 1, 'month' => '09'],
                ['id' => 4, 'slug' => 'wordpress-security-tips', 'date' => '2024-08-23T14:15:00', 'title' => '5 Common WordPress Security Vulnerabilities and How to Protect Your Site', 'excerpt' => 'WordPress powers over 40% of all websites worldwide.', 'author' => 1, 'cat' => 2, 'month' => '08'],
                ['id' => 3, 'slug' => 'partnership-cloudsecure', 'date' => '2024-07-05T09:00:00', 'title' => 'New Partnership with CloudSecure for Enhanced DDoS Protection', 'excerpt' => 'We are excited to announce our new partnership with CloudSecure.', 'author' => 2, 'cat' => 3, 'month' => '07'],
                ['id' => 2, 'slug' => 'seo-basics-meta-tags', 'date' => '2024-06-18T11:45:00', 'title' => 'SEO Basics: How to Properly Implement Meta Tags and Structured Data', 'excerpt' => 'Search engine optimization starts with the fundamentals.', 'author' => 1, 'cat' => 4, 'month' => '06'],
                ['id' => 1, 'slug' => 'summer-special-website-audit', 'date' => '2024-05-02T08:30:00', 'title' => 'Summer Special: Free Website Audit for New Clients', 'excerpt' => 'Take advantage of our free website audit.', 'author' => 2, 'cat' => 5, 'month' => '05'],
            ];

            $jsonPosts = [];
            foreach ($posts as $p) {
                $year = substr($p['date'], 0, 4);
                $link = $siteUrl . "/{$year}/{$p['month']}/{$p['slug']}/";
                $jsonPosts[] = [
                    'id'       => $p['id'],
                    'date'     => $p['date'],
                    'date_gmt' => $p['date'],
                    'guid'     => ['rendered' => $siteUrl . '/?p=' . $p['id']],
                    'modified' => $p['date'],
                    'slug'     => $p['slug'],
                    'status'   => 'publish',
                    'type'     => 'post',
                    'link'     => $link,
                    'title'    => ['rendered' => $p['title']],
                    'content'  => ['rendered' => '<p>' . $p['excerpt'] . '</p>', 'protected' => false],
                    'excerpt'  => ['rendered' => '<p>' . $p['excerpt'] . '</p>', 'protected' => false],
                    'author'   => $p['author'],
                    'categories' => [$p['cat']],
                    'tags'     => [],
                ];
            }
            $response->json($jsonPosts);
            return $response;
        }

        // /wp-json/ - API index
        $response->json([
            'name'            => $data['site_name'],
            'description'     => $data['tagline'] ?? '',
            'url'             => $siteUrl,
            'home'            => $siteUrl,
            'gmt_offset'      => '0',
            'timezone_string' => 'UTC',
            'namespaces'      => ['oembed/1.0', 'wp/v2', 'wp-site-health/v1'],
            'authentication'  => [],
            'routes'          => [
                '/wp/v2'               => ['namespace' => 'wp/v2', 'methods' => ['GET']],
                '/wp/v2/posts'         => ['namespace' => 'wp/v2', 'methods' => ['GET', 'POST']],
                '/wp/v2/pages'         => ['namespace' => 'wp/v2', 'methods' => ['GET', 'POST']],
                '/wp/v2/media'         => ['namespace' => 'wp/v2', 'methods' => ['GET', 'POST']],
                '/wp/v2/types'         => ['namespace' => 'wp/v2', 'methods' => ['GET']],
                '/wp/v2/statuses'      => ['namespace' => 'wp/v2', 'methods' => ['GET']],
                '/wp/v2/taxonomies'    => ['namespace' => 'wp/v2', 'methods' => ['GET']],
                '/wp/v2/categories'    => ['namespace' => 'wp/v2', 'methods' => ['GET', 'POST']],
                '/wp/v2/tags'          => ['namespace' => 'wp/v2', 'methods' => ['GET', 'POST']],
                '/wp/v2/users'         => ['namespace' => 'wp/v2', 'methods' => ['GET', 'POST']],
                '/wp/v2/comments'      => ['namespace' => 'wp/v2', 'methods' => ['GET', 'POST']],
                '/wp/v2/search'        => ['namespace' => 'wp/v2', 'methods' => ['GET']],
                '/wp/v2/settings'      => ['namespace' => 'wp/v2', 'methods' => ['GET', 'POST']],
                '/wp/v2/themes'        => ['namespace' => 'wp/v2', 'methods' => ['GET']],
                '/wp/v2/plugins'       => ['namespace' => 'wp/v2', 'methods' => ['GET', 'POST']],
            ],
            '_links' => [
                'help' => [['href' => 'https://developer.wordpress.org/rest-api/']],
            ],
        ]);

        return $response;
    }

    /**
     * Handle Drupal JSON:API routes.
     */
    private function handleDrupal(
        string $path,
        Request $request,
        Response $response,
        CmsProfile $profile
    ): Response {
        $data = $profile->getTemplateData();
        $siteUrl = $data['site_url'] ?: '';

        // /jsonapi/user/user - User enumeration
        if (str_starts_with($path, '/jsonapi/user/user')) {
            $response->json([
                'jsonapi' => ['version' => '1.0', 'meta' => ['links' => ['self' => ['href' => 'http://jsonapi.org/format/1.0/']]]],
                'data'    => [
                    [
                        'type'       => 'user--user',
                        'id'         => 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
                        'attributes' => [
                            'display_name' => 'admin',
                            'drupal_internal__uid' => 1,
                            'name'    => 'admin',
                            'status'  => true,
                            'created' => '2024-01-15T10:30:00+00:00',
                            'changed' => '2024-06-20T14:22:00+00:00',
                        ],
                        'links' => ['self' => ['href' => $siteUrl . '/jsonapi/user/user/a1b2c3d4-e5f6-7890-abcd-ef1234567890']],
                    ],
                ],
                'links' => ['self' => ['href' => $siteUrl . '/jsonapi/user/user']],
            ]);
            return $response;
        }

        // /jsonapi/node/article - Fake articles
        if (str_starts_with($path, '/jsonapi/node/article')) {
            $response->json([
                'jsonapi' => ['version' => '1.0'],
                'data'    => [
                    [
                        'type'       => 'node--article',
                        'id'         => 'f1e2d3c4-b5a6-7890-fedc-ba0987654321',
                        'attributes' => [
                            'title'   => 'Welcome to our Drupal site',
                            'status'  => true,
                            'created' => '2024-01-15T10:30:00+00:00',
                            'body'    => ['value' => '<p>This is our first article.</p>', 'format' => 'basic_html'],
                        ],
                    ],
                ],
            ]);
            return $response;
        }

        // /jsonapi/ - API index
        $response->json([
            'jsonapi' => ['version' => '1.0', 'meta' => ['links' => ['self' => ['href' => 'http://jsonapi.org/format/1.0/']]]],
            'data'    => [],
            'meta'    => ['links' => ['me' => ['href' => $siteUrl . '/jsonapi/user/user']]],
            'links'   => [
                'self'                => ['href' => $siteUrl . '/jsonapi'],
                'node--article'       => ['href' => $siteUrl . '/jsonapi/node/article'],
                'node--page'          => ['href' => $siteUrl . '/jsonapi/node/page'],
                'user--user'          => ['href' => $siteUrl . '/jsonapi/user/user'],
                'taxonomy_term--tags' => ['href' => $siteUrl . '/jsonapi/taxonomy_term/tags'],
            ],
        ]);

        return $response;
    }

    /**
     * Handle Joomla API routes.
     */
    private function handleJoomla(
        string $path,
        Request $request,
        Response $response,
        CmsProfile $profile
    ): Response {
        $data = $profile->getTemplateData();
        $siteUrl = $data['site_url'] ?: '';

        // /api/v1/users - User listing (requires auth in real Joomla)
        if (str_starts_with($path, '/api/v1/users') || str_starts_with($path, '/api/users')) {
            $response->setStatusCode(401);
            $response->json([
                'errors' => [
                    [
                        'title'  => 'Forbidden',
                        'code'   => 403,
                        'detail' => 'You are not authorised to access this resource.',
                    ],
                ],
            ], 401);
            return $response;
        }

        // /api/v1/content/articles
        if (str_starts_with($path, '/api/v1/content/articles') || str_starts_with($path, '/api/content/articles')) {
            $response->json([
                'links' => ['self' => $siteUrl . '/api/v1/content/articles'],
                'data'  => [
                    [
                        'type'       => 'articles',
                        'id'         => '1',
                        'attributes' => [
                            'title'     => 'Getting Started',
                            'alias'     => 'getting-started',
                            'introtext' => '<p>Welcome to our Joomla website.</p>',
                            'state'     => 1,
                            'created'   => '2024-01-15 10:30:00',
                        ],
                    ],
                ],
                'meta' => ['total-pages' => 1],
            ]);
            return $response;
        }

        // /api/ - API index
        $response->json([
            'links' => ['self' => $siteUrl . '/api/index.php/v1'],
            'data'  => [
                'type'       => 'application',
                'id'         => 'joomla',
                'attributes' => [
                    'title'   => $data['site_name'],
                    'version' => $data['joomla_version'],
                ],
            ],
        ]);

        return $response;
    }
}
