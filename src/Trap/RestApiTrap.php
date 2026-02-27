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
            $now = gmdate('Y-m-d\TH:i:s');
            $response->json([
                [
                    'id'       => 1,
                    'date'     => $now,
                    'date_gmt' => $now,
                    'guid'     => ['rendered' => $siteUrl . '/?p=1'],
                    'modified' => $now,
                    'slug'     => 'hello-world',
                    'status'   => 'publish',
                    'type'     => 'post',
                    'link'     => $siteUrl . '/hello-world/',
                    'title'    => ['rendered' => 'Hello world!'],
                    'content'  => ['rendered' => '<p>Welcome to our site. This is your first post. Edit or delete it, then start writing!</p>', 'protected' => false],
                    'excerpt'  => ['rendered' => '<p>Welcome to our site. This is your first post.</p>', 'protected' => false],
                    'author'   => 1,
                    'categories' => [1],
                    'tags'     => [],
                ],
            ]);
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
