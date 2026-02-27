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
 * Miscellaneous static-file trap.
 *
 * Serves robots.txt, RSS feed, wp-cron.php, sitemap.xml, and other
 * standard CMS files that scanners and crawlers expect to find.
 */
class MiscTrap implements TrapInterface, DatabaseAwareInterface
{
    private ?Database $db = null;

    public function getName(): string
    {
        return 'misc';
    }

    public function setDatabase(Database $db): void
    {
        $this->db = $db;
    }

    public function handle(Request $request, Response $response, CmsProfile $profile): Response
    {
        foreach ($profile->getDefaultHeaders() as $name => $value) {
            $response->setHeader($name, $value);
        }

        $path = $request->getPath();

        if ($path === '/robots.txt') {
            return $this->serveRobotsTxt($response, $profile);
        }

        if ($path === '/feed/' || $path === '/feed' || $path === '/rss.xml') {
            return $this->serveRssFeed($response, $profile);
        }

        if ($path === '/wp-cron.php') {
            return $this->serveWpCron($response);
        }

        if ($path === '/sitemap.xml') {
            return $this->serveSitemap($response, $profile);
        }

        if ($path === '/wp-includes/js/jquery/jquery.min.js') {
            return $this->serveJqueryForbidden($response);
        }

        // Fallback: 404
        $notFound = new NotFoundTrap();
        return $notFound->handle($request, $response, $profile);
    }

    private function serveRobotsTxt(Response $response, CmsProfile $profile): Response
    {
        $response->setStatusCode(200);
        $response->setContentType('text/plain; charset=UTF-8');

        $profileName = $profile->getName();
        $body = "User-agent: *\n";

        switch ($profileName) {
            case 'drupal':
                $body .= "Disallow: /admin/\n"
                    . "Disallow: /user/login\n"
                    . "Disallow: /user/register\n"
                    . "Disallow: /core/\n"
                    . "Disallow: /sites/\n";
                break;

            case 'joomla':
                $body .= "Disallow: /administrator/\n"
                    . "Disallow: /cache/\n"
                    . "Disallow: /tmp/\n"
                    . "Disallow: /libraries/\n";
                break;

            case 'wordpress':
            default:
                $body .= "Disallow: /wp-admin/\n"
                    . "Allow: /wp-admin/admin-ajax.php\n";
                break;
        }

        $body .= "\nSitemap: /sitemap.xml\n";
        $response->setBody($body);
        return $response;
    }

    private function serveRssFeed(Response $response, CmsProfile $profile): Response
    {
        $data = $profile->getTemplateData();
        $siteName = htmlspecialchars($data['site_name'] ?? 'My Site', ENT_XML1, 'UTF-8');
        $tagline = htmlspecialchars($data['tagline'] ?? $data['site_name'] ?? 'A website', ENT_XML1, 'UTF-8');
        $now = gmdate('D, d M Y H:i:s') . ' +0000';
        $profileName = $profile->getName();

        // Build items from generated content or fallback
        $items = '';
        if ($this->db !== null) {
            try {
                $repo = new ContentRepository($this->db);
                $posts = $repo->getPublished($profileName, 10);
                foreach ($posts as $post) {
                    $url = ContentUrlGenerator::getPostUrl($post);
                    $title = htmlspecialchars($post['title'] ?? '', ENT_XML1, 'UTF-8');
                    $author = htmlspecialchars($post['author'] ?? 'admin', ENT_XML1, 'UTF-8');
                    $pubDate = gmdate('D, d M Y H:i:s', strtotime($post['published_date'])) . ' +0000';
                    $excerpt = htmlspecialchars($post['excerpt'] ?? '', ENT_XML1, 'UTF-8');
                    $category = htmlspecialchars($post['category'] ?? 'Uncategorized', ENT_XML1, 'UTF-8');
                    $content = '<![CDATA[' . ($post['content'] ?? '') . ']]>';
                    $items .= <<<XML

    <item>
        <title>{$title}</title>
        <link>{$url}</link>
        <dc:creator><![CDATA[{$author}]]></dc:creator>
        <pubDate>{$pubDate}</pubDate>
        <category><![CDATA[{$category}]]></category>
        <guid isPermaLink="false">{$url}</guid>
        <description><![CDATA[{$excerpt}]]></description>
        <content:encoded>{$content}</content:encoded>
    </item>
XML;
                }
            } catch (\Throwable $e) {
                // Fall through to default item
            }
        }

        if ($items === '') {
            $items = <<<XML

    <item>
        <title>Hello world!</title>
        <link>/hello-world/</link>
        <dc:creator><![CDATA[admin]]></dc:creator>
        <pubDate>{$now}</pubDate>
        <category><![CDATA[Uncategorized]]></category>
        <guid isPermaLink="false">/?p=1</guid>
        <description><![CDATA[Welcome to our site. This is your first post. Edit or delete it, then start writing!]]></description>
        <content:encoded><![CDATA[<p>Welcome to our site. This is your first post. Edit or delete it, then start writing!</p>]]></content:encoded>
    </item>
XML;
        }

        // CMS-specific generator
        switch ($profileName) {
            case 'drupal':
                $generator = 'Drupal ' . $profile->getVersion() . ' (https://www.drupal.org)';
                break;
            case 'joomla':
                $generator = 'Joomla! ' . $profile->getVersion();
                break;
            default:
                $generator = 'https://wordpress.org/?v=' . $profile->getVersion();
                break;
        }

        $response->setStatusCode(200);
        $response->setContentType('application/rss+xml; charset=UTF-8');
        $response->setBody(<<<XML
<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"
    xmlns:content="http://purl.org/rss/1.0/modules/content/"
    xmlns:dc="http://purl.org/dc/elements/1.1/"
    xmlns:atom="http://www.w3.org/2005/Atom"
    xmlns:sy="http://purl.org/rss/1.0/modules/syndication/">
<channel>
    <title>{$siteName}</title>
    <link>/</link>
    <description>{$tagline}</description>
    <lastBuildDate>{$now}</lastBuildDate>
    <language>en-US</language>
    <sy:updatePeriod>hourly</sy:updatePeriod>
    <sy:updateFrequency>1</sy:updateFrequency>
    <generator>{$generator}</generator>{$items}
</channel>
</rss>
XML);
        return $response;
    }

    private function serveWpCron(Response $response): Response
    {
        $response->setStatusCode(200);
        $response->setContentType('text/html; charset=UTF-8');
        $response->setBody('');
        return $response;
    }

    private function serveSitemap(Response $response, CmsProfile $profile): Response
    {
        $now = gmdate('Y-m-d\TH:i:s+00:00');
        $profileName = $profile->getName();

        $urls = <<<XML

    <url>
        <loc>/</loc>
        <lastmod>{$now}</lastmod>
        <changefreq>daily</changefreq>
        <priority>1.0</priority>
    </url>
XML;

        // Add generated content URLs
        if ($this->db !== null) {
            try {
                $repo = new ContentRepository($this->db);
                $entries = $repo->getForSitemap($profileName);
                foreach ($entries as $entry) {
                    $entry['cms_profile'] = $profileName;
                    $url = htmlspecialchars(ContentUrlGenerator::getPostUrl($entry), ENT_XML1, 'UTF-8');
                    $lastmod = gmdate('Y-m-d\TH:i:s+00:00', strtotime($entry['published_date']));
                    $urls .= <<<XML

    <url>
        <loc>{$url}</loc>
        <lastmod>{$lastmod}</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.6</priority>
    </url>
XML;
                }
            } catch (\Throwable $e) {
                // Fall through with just the homepage
            }
        }

        // Add static fallback entries if no generated content
        if ($this->db === null) {
            $urls .= <<<XML

    <url>
        <loc>/hello-world/</loc>
        <lastmod>{$now}</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.8</priority>
    </url>
    <url>
        <loc>/sample-page/</loc>
        <lastmod>{$now}</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.8</priority>
    </url>
XML;
        }

        $response->setStatusCode(200);
        $response->setContentType('application/xml; charset=UTF-8');
        $response->setBody(<<<XML
<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet type="text/xsl" href="/wp-sitemap.xsl" ?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{$urls}
</urlset>
XML);
        return $response;
    }

    private function serveJqueryForbidden(Response $response): Response
    {
        $response->setStatusCode(403);
        $response->setContentType('text/html; charset=UTF-8');
        $response->setBody(<<<'HTML'
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.58 (Ubuntu) Server at localhost Port 80</address>
</body></html>
HTML);
        return $response;
    }
}
