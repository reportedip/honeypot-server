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

        // wp-includes JS/CSS assets - serve minimal content with correct Content-Type
        if (preg_match('#^/wp-includes/(js|css)/.+\.(js|css)$#', $path, $m)) {
            return $this->serveMinimalAsset($response, strtolower($m[2]));
        }

        // Fallback: 404
        $notFound = new NotFoundTrap();
        return $notFound->handle($request, $response, $profile);
    }

    /**
     * Serve a minimal empty asset with the correct Content-Type.
     */
    private function serveMinimalAsset(Response $response, string $extension): Response
    {
        $response->setStatusCode(200);
        if ($extension === 'css') {
            $response->setContentType('text/css; charset=UTF-8');
            $response->setBody("/* WordPress core stylesheet */\n");
        } else {
            $response->setContentType('application/javascript; charset=UTF-8');
            $response->setBody("/* WordPress core script */\n");
        }
        return $response;
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
            $lang = $data['content_language'] ?? 'en';
            $fallbackItems = ($lang === 'de') ? [
                ['title' => 'Warum responsives Webdesign 2024 wichtiger denn je ist', 'slug' => 'responsives-webdesign-2024', 'date' => '2024-09-12', 'author' => 'admin', 'cat' => 'Webdesign', 'desc' => 'Mobile Endgeraete machen mittlerweile ueber 60% des weltweiten Web-Traffics aus.'],
                ['title' => '5 haeufige Sicherheitsluecken in WordPress und wie Sie sich schuetzen', 'slug' => 'wordpress-sicherheitstipps', 'date' => '2024-08-23', 'author' => 'admin', 'cat' => 'Sicherheit', 'desc' => 'WordPress betreibt ueber 40% aller Websites weltweit und ist damit ein beliebtes Ziel fuer Angreifer.'],
                ['title' => 'Neue Partnerschaft mit CloudSecure fuer erweiterten DDoS-Schutz', 'slug' => 'partnerschaft-cloudsecure', 'date' => '2024-07-05', 'author' => 'editor', 'cat' => 'Unternehmen', 'desc' => 'Wir freuen uns, unsere neue Partnerschaft mit CloudSecure bekannt zu geben.'],
                ['title' => 'SEO-Grundlagen: Meta-Tags und strukturierte Daten richtig einsetzen', 'slug' => 'seo-grundlagen-meta-tags', 'date' => '2024-06-18', 'author' => 'admin', 'cat' => 'SEO', 'desc' => 'Suchmaschinenoptimierung beginnt bei den Grundlagen.'],
                ['title' => 'Sommeraktion: Kostenlose Website-Analyse fuer Neukunden', 'slug' => 'sommeraktion-website-analyse', 'date' => '2024-05-02', 'author' => 'editor', 'cat' => 'Angebote', 'desc' => 'Nutzen Sie unsere kostenlose Website-Analyse und erfahren Sie, wie Sie Ihre Website verbessern koennen.'],
            ] : [
                ['title' => 'Why Responsive Web Design Matters More Than Ever in 2024', 'slug' => 'responsive-web-design-2024', 'date' => '2024-09-12', 'author' => 'admin', 'cat' => 'Web Design', 'desc' => 'Mobile devices now account for over 60% of global web traffic.'],
                ['title' => '5 Common WordPress Security Vulnerabilities and How to Protect Your Site', 'slug' => 'wordpress-security-tips', 'date' => '2024-08-23', 'author' => 'admin', 'cat' => 'Security', 'desc' => 'WordPress powers over 40% of all websites worldwide, making it a prime target for attackers.'],
                ['title' => 'New Partnership with CloudSecure for Enhanced DDoS Protection', 'slug' => 'partnership-cloudsecure', 'date' => '2024-07-05', 'author' => 'editor', 'cat' => 'Company News', 'desc' => 'We are excited to announce our new partnership with CloudSecure.'],
                ['title' => 'SEO Basics: How to Properly Implement Meta Tags and Structured Data', 'slug' => 'seo-basics-meta-tags', 'date' => '2024-06-18', 'author' => 'admin', 'cat' => 'SEO', 'desc' => 'Search engine optimization starts with the fundamentals.'],
                ['title' => 'Summer Special: Free Website Audit for New Clients', 'slug' => 'summer-special-website-audit', 'date' => '2024-05-02', 'author' => 'editor', 'cat' => 'Offers', 'desc' => 'Take advantage of our free website audit and discover how to improve your website.'],
            ];
            foreach ($fallbackItems as $fi) {
                $fiTitle = htmlspecialchars($fi['title'], ENT_XML1, 'UTF-8');
                $fiDate = substr($fi['date'], 0, 4);
                $fiMonth = substr($fi['date'], 5, 2);
                $fiLink = "/{$fiDate}/{$fiMonth}/{$fi['slug']}/";
                $fiPubDate = gmdate('D, d M Y H:i:s', strtotime($fi['date'])) . ' +0000';
                $fiCat = htmlspecialchars($fi['cat'], ENT_XML1, 'UTF-8');
                $fiDesc = htmlspecialchars($fi['desc'], ENT_XML1, 'UTF-8');
                $items .= <<<XML

    <item>
        <title>{$fiTitle}</title>
        <link>{$fiLink}</link>
        <dc:creator><![CDATA[{$fi['author']}]]></dc:creator>
        <pubDate>{$fiPubDate}</pubDate>
        <category><![CDATA[{$fiCat}]]></category>
        <guid isPermaLink="false">{$fiLink}</guid>
        <description><![CDATA[{$fiDesc}]]></description>
        <content:encoded><![CDATA[<p>{$fiDesc}</p>]]></content:encoded>
    </item>
XML;
            }
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
    <language>{$data['language']}</language>
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
            $data = $profile->getTemplateData();
            $lang = $data['content_language'] ?? 'en';
            $fallbackSlugs = ($lang === 'de')
                ? [
                    ['y' => '2024', 'm' => '09', 's' => 'responsives-webdesign-2024', 'd' => '2024-09-12'],
                    ['y' => '2024', 'm' => '08', 's' => 'wordpress-sicherheitstipps', 'd' => '2024-08-23'],
                    ['y' => '2024', 'm' => '07', 's' => 'partnerschaft-cloudsecure', 'd' => '2024-07-05'],
                    ['y' => '2024', 'm' => '06', 's' => 'seo-grundlagen-meta-tags', 'd' => '2024-06-18'],
                    ['y' => '2024', 'm' => '05', 's' => 'sommeraktion-website-analyse', 'd' => '2024-05-02'],
                ]
                : [
                    ['y' => '2024', 'm' => '09', 's' => 'responsive-web-design-2024', 'd' => '2024-09-12'],
                    ['y' => '2024', 'm' => '08', 's' => 'wordpress-security-tips', 'd' => '2024-08-23'],
                    ['y' => '2024', 'm' => '07', 's' => 'partnership-cloudsecure', 'd' => '2024-07-05'],
                    ['y' => '2024', 'm' => '06', 's' => 'seo-basics-meta-tags', 'd' => '2024-06-18'],
                    ['y' => '2024', 'm' => '05', 's' => 'summer-special-website-audit', 'd' => '2024-05-02'],
                ];
            foreach ($fallbackSlugs as $fs) {
                $fLoc = "/{$fs['y']}/{$fs['m']}/{$fs['s']}/";
                $fMod = gmdate('Y-m-d\TH:i:s+00:00', strtotime($fs['d']));
                $urls .= <<<XML

    <url>
        <loc>{$fLoc}</loc>
        <lastmod>{$fMod}</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.6</priority>
    </url>
XML;
            }
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

}
