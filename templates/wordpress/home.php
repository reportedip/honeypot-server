<?php
/**
 * WordPress homepage template.
 *
 * Variables: $site_name, $site_url, $wp_version, $tagline, $theme,
 *            $language, $content_language, $request_uri
 *            Optional: $is_search_page, $search_term, $search_results,
 *                      $is_contact_page, $contact_success, $contact_message,
 *                      $show_contact_form, $comment_notice, $message,
 *                      $is_author_page, $author_name,
 *                      $is_user_profile (Drupal), $user_name, $user_id
 */

$siteUrl = htmlspecialchars($site_url ?? '', ENT_QUOTES, 'UTF-8');
$siteName = htmlspecialchars($site_name ?? 'My WordPress Site', ENT_QUOTES, 'UTF-8');
$taglineEsc = htmlspecialchars($tagline ?? 'Just another WordPress site', ENT_QUOTES, 'UTF-8');
$version = htmlspecialchars($wp_version ?? '6.4.2', ENT_QUOTES, 'UTF-8');
$lang = $content_language ?? 'en';
$isGerman = ($lang === 'de');
$year = date('Y');

// Fallback articles - realistic business website content
if ($isGerman) {
    $fallbackArticles = [
        [
            'title' => 'Warum responsives Webdesign 2024 wichtiger denn je ist',
            'slug' => 'responsives-webdesign-2024',
            'url' => $siteUrl . '/2024/09/responsives-webdesign-2024/',
            'date' => 'September 12, 2024',
            'date_raw' => '2024-09-12',
            'author' => 'admin',
            'category' => 'Webdesign',
            'excerpt' => 'Mobile Endger&auml;te machen mittlerweile &uuml;ber 60% des weltweiten Web-Traffics aus. Wir erkl&auml;ren, warum ein responsives Design nicht nur f&uuml;r die Nutzererfahrung, sondern auch f&uuml;r Ihr Google-Ranking entscheidend ist.',
        ],
        [
            'title' => '5 h&auml;ufige Sicherheitsl&uuml;cken in WordPress und wie Sie sich sch&uuml;tzen',
            'slug' => 'wordpress-sicherheitstipps',
            'url' => $siteUrl . '/2024/08/wordpress-sicherheitstipps/',
            'date' => 'August 23, 2024',
            'date_raw' => '2024-08-23',
            'author' => 'admin',
            'category' => 'Sicherheit',
            'excerpt' => 'WordPress betreibt &uuml;ber 40% aller Websites weltweit &ndash; und ist damit ein beliebtes Ziel f&uuml;r Angreifer. Erfahren Sie, welche Schwachstellen am h&auml;ufigsten ausgenutzt werden und wie Sie Ihre Seite effektiv absichern.',
        ],
        [
            'title' => 'Neue Partnerschaft mit CloudSecure f&uuml;r erweiterten DDoS-Schutz',
            'slug' => 'partnerschaft-cloudsecure',
            'url' => $siteUrl . '/2024/07/partnerschaft-cloudsecure/',
            'date' => 'July 5, 2024',
            'date_raw' => '2024-07-05',
            'author' => 'editor',
            'category' => 'Unternehmen',
            'excerpt' => 'Wir freuen uns, unsere neue Partnerschaft mit CloudSecure bekannt zu geben. Ab sofort profitieren alle unsere Hosting-Kunden von einem erweiterten DDoS-Schutz ohne zus&auml;tzliche Kosten.',
        ],
        [
            'title' => 'SEO-Grundlagen: Meta-Tags und strukturierte Daten richtig einsetzen',
            'slug' => 'seo-grundlagen-meta-tags',
            'url' => $siteUrl . '/2024/06/seo-grundlagen-meta-tags/',
            'date' => 'June 18, 2024',
            'date_raw' => '2024-06-18',
            'author' => 'admin',
            'category' => 'SEO',
            'excerpt' => 'Suchmaschinenoptimierung beginnt bei den Grundlagen. In diesem Beitrag zeigen wir Ihnen, wie Sie Meta-Tags und Schema.org-Markup korrekt implementieren, um Ihre Sichtbarkeit in den Suchergebnissen zu verbessern.',
        ],
        [
            'title' => 'Sommeraktion: Kostenlose Website-Analyse f&uuml;r Neukunden',
            'slug' => 'sommeraktion-website-analyse',
            'url' => $siteUrl . '/2024/05/sommeraktion-website-analyse/',
            'date' => 'May 2, 2024',
            'date_raw' => '2024-05-02',
            'author' => 'editor',
            'category' => 'Angebote',
            'excerpt' => 'Nur f&uuml;r begrenzte Zeit: Nutzen Sie unsere kostenlose Website-Analyse und erfahren Sie, wie Sie Performance, Sicherheit und SEO Ihrer bestehenden Website verbessern k&ouml;nnen.',
        ],
    ];
    $fallbackCategories = ['Webdesign', 'Sicherheit', 'Unternehmen', 'SEO', 'Angebote'];
    $navServices = 'Leistungen';
    $navAbout = '&Uuml;ber uns';
    $navBlog = 'Blog';
    $navContact = 'Kontakt';
} else {
    $fallbackArticles = [
        [
            'title' => 'Why Responsive Web Design Matters More Than Ever in 2024',
            'slug' => 'responsive-web-design-2024',
            'url' => $siteUrl . '/2024/09/responsive-web-design-2024/',
            'date' => 'September 12, 2024',
            'date_raw' => '2024-09-12',
            'author' => 'admin',
            'category' => 'Web Design',
            'excerpt' => 'Mobile devices now account for over 60% of global web traffic. We explain why responsive design is crucial not just for user experience, but also for your Google ranking and overall business success.',
        ],
        [
            'title' => '5 Common WordPress Security Vulnerabilities and How to Protect Your Site',
            'slug' => 'wordpress-security-tips',
            'url' => $siteUrl . '/2024/08/wordpress-security-tips/',
            'date' => 'August 23, 2024',
            'date_raw' => '2024-08-23',
            'author' => 'admin',
            'category' => 'Security',
            'excerpt' => 'WordPress powers over 40% of all websites worldwide, making it a prime target for attackers. Learn about the most commonly exploited vulnerabilities and how to effectively secure your site.',
        ],
        [
            'title' => 'New Partnership with CloudSecure for Enhanced DDoS Protection',
            'slug' => 'partnership-cloudsecure',
            'url' => $siteUrl . '/2024/07/partnership-cloudsecure/',
            'date' => 'July 5, 2024',
            'date_raw' => '2024-07-05',
            'author' => 'editor',
            'category' => 'Company News',
            'excerpt' => 'We are excited to announce our new partnership with CloudSecure. Starting today, all our hosting clients benefit from enhanced DDoS protection at no additional cost.',
        ],
        [
            'title' => 'SEO Basics: How to Properly Implement Meta Tags and Structured Data',
            'slug' => 'seo-basics-meta-tags',
            'url' => $siteUrl . '/2024/06/seo-basics-meta-tags/',
            'date' => 'June 18, 2024',
            'date_raw' => '2024-06-18',
            'author' => 'admin',
            'category' => 'SEO',
            'excerpt' => 'Search engine optimization starts with the fundamentals. In this post, we show you how to correctly implement meta tags and Schema.org markup to improve your visibility in search results.',
        ],
        [
            'title' => 'Summer Special: Free Website Audit for New Clients',
            'slug' => 'summer-special-website-audit',
            'url' => $siteUrl . '/2024/05/summer-special-website-audit/',
            'date' => 'May 2, 2024',
            'date_raw' => '2024-05-02',
            'author' => 'editor',
            'category' => 'Offers',
            'excerpt' => 'For a limited time only: Take advantage of our free website audit and discover how to improve the performance, security, and SEO of your existing website.',
        ],
    ];
    $fallbackCategories = ['Web Design', 'Security', 'Company News', 'SEO', 'Offers'];
    $navServices = 'Services';
    $navAbout = 'About';
    $navBlog = 'Blog';
    $navContact = 'Contact';
}
?>
<!DOCTYPE html>
<html lang="<?php echo htmlspecialchars($language ?? 'en-US', ENT_QUOTES, 'UTF-8'); ?>">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="WordPress <?php echo $version; ?>">
<title><?php
if (!empty($is_search_page)) {
    echo 'Search Results for &#8220;' . ($search_term ?? '') . '&#8221; &#8211; ' . $siteName;
} elseif (!empty($is_contact_page)) {
    echo 'Contact &#8211; ' . $siteName;
} elseif (!empty($is_author_page)) {
    echo htmlspecialchars($author_name ?? 'admin', ENT_QUOTES, 'UTF-8') . ', Author at ' . $siteName;
} else {
    echo $siteName . ' &#8211; ' . $taglineEsc;
}
?></title>
<link rel="alternate" type="application/rss+xml" title="<?php echo $siteName; ?> &raquo; Feed" href="<?php echo $siteUrl; ?>/feed/">
<link rel="alternate" type="application/rss+xml" title="<?php echo $siteName; ?> &raquo; Comments Feed" href="<?php echo $siteUrl; ?>/comments/feed/">
<link rel="pingback" href="<?php echo $siteUrl; ?>/xmlrpc.php">
<link rel='stylesheet' id='wp-block-library-css' href='<?php echo $siteUrl; ?>/wp-includes/css/dist/block-library/style.min.css?ver=<?php echo $version; ?>' media='all' />
<link rel='stylesheet' id='twentytwentyfour-style-css' href='<?php echo $siteUrl; ?>/wp-content/themes/twentytwentyfour/style.css?ver=1.0' media='all' />
<link rel='stylesheet' id='avada-stylesheet-css' href='<?php echo $siteUrl; ?>/wp-content/themes/Avada/assets/css/style.min.css?ver=7.11.4' media='all' />
<link rel='stylesheet' id='contact-form-7-css' href='<?php echo $siteUrl; ?>/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.8.4' media='all' />
<link rel='stylesheet' id='woocommerce-layout-css' href='<?php echo $siteUrl; ?>/wp-content/plugins/woocommerce/assets/css/woocommerce-layout.css?ver=8.3.1' media='all' />
<link rel='stylesheet' id='elementor-frontend-css' href='<?php echo $siteUrl; ?>/wp-content/plugins/elementor/assets/css/frontend.min.css?ver=3.18.3' media='all' />
<script>
window._wpemojiSettings = {"baseUrl":"https:\/\/s.w.org\/images\/core\/emoji\/15.0.3\/72x72\/","ext":".png","svgUrl":"https:\/\/s.w.org\/images\/core\/emoji\/15.0.3\/svg\/","svgExt":".svg","source":{"concatemoji":"<?php echo $siteUrl; ?>\/wp-includes\/js\/wp-emoji-release.min.js?ver=<?php echo $version; ?>"}};
!function(o,n,e){var s=o.document,a=s.createElement("script");a.src=n,s.head.appendChild(a)}(window,"<?php echo $siteUrl; ?>/wp-includes/js/wp-emoji-release.min.js?ver=<?php echo $version; ?>");
</script>
<style type="text/css">
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif;font-size:16px;line-height:1.7;color:#333;background:#f0f0f0}
a{color:#0073aa;text-decoration:none}
a:hover{color:#005177;text-decoration:underline}
.site-header{background:#fff;border-bottom:1px solid #ddd;padding:30px 0}
.site-header .container{max-width:1100px;margin:0 auto;padding:0 20px}
.site-title{font-size:28px;font-weight:700;margin:0}
.site-title a{color:#333;text-decoration:none}
.site-description{color:#777;font-size:14px;margin-top:4px}
.site-nav{background:#23282d;padding:0}
.site-nav ul{list-style:none;max-width:1100px;margin:0 auto;padding:0 20px;display:flex}
.site-nav li{margin:0}
.site-nav a{display:block;padding:12px 18px;color:#eee;font-size:14px;text-decoration:none}
.site-nav a:hover{background:#32373c;color:#fff}
.site-content{max-width:1100px;margin:30px auto;padding:0 20px;display:flex;gap:30px}
.main-content{flex:1;min-width:0}
.sidebar{width:300px;flex-shrink:0}
.post{background:#fff;padding:30px;margin-bottom:30px;border:1px solid #ddd}
.post-title{font-size:24px;margin-bottom:10px}
.post-title a{color:#333}
.post-meta{color:#777;font-size:13px;margin-bottom:15px}
.post-content p{margin-bottom:15px}
.read-more{display:inline-block;margin-top:10px;padding:8px 16px;background:#0073aa;color:#fff;font-size:13px;border-radius:3px}
.read-more:hover{background:#005177;color:#fff;text-decoration:none}
.widget{background:#fff;padding:20px;margin-bottom:20px;border:1px solid #ddd}
.widget-title{font-size:16px;font-weight:700;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #eee}
.widget ul{list-style:none;padding:0}
.widget li{padding:5px 0;border-bottom:1px solid #f5f5f5}
.widget li:last-child{border-bottom:none}
.site-footer{background:#23282d;color:#aaa;text-align:center;padding:20px;font-size:13px;margin-top:40px}
.site-footer a{color:#ccc}
.comment-form-area{background:#fff;padding:30px;border:1px solid #ddd;margin-bottom:30px}
.comment-form-area h3{margin-bottom:15px;font-size:20px}
.comment-form-area input[type="text"],
.comment-form-area input[type="email"],
.comment-form-area input[type="url"],
.comment-form-area textarea{width:100%;padding:8px 12px;border:1px solid #ddd;font-size:14px;margin-bottom:10px;font-family:inherit}
.comment-form-area textarea{height:120px;resize:vertical}
.comment-form-area .submit-btn{background:#0073aa;color:#fff;border:none;padding:10px 20px;cursor:pointer;font-size:14px;border-radius:3px}
.notice{background:#fff3cd;border:1px solid #ffc107;padding:12px 20px;margin-bottom:20px;color:#856404;border-radius:3px}
.contact-success{background:#d4edda;border:1px solid #28a745;padding:12px 20px;margin-bottom:20px;color:#155724;border-radius:3px}
.search-results h2{margin-bottom:20px}
.search-form{margin-bottom:20px}
.search-form input[type="search"]{padding:8px 12px;width:300px;border:1px solid #ddd;font-size:14px}
.search-form button{padding:8px 16px;background:#0073aa;color:#fff;border:none;cursor:pointer;font-size:14px}
@media(max-width:768px){.site-content{flex-direction:column}.sidebar{width:100%}}
</style>
</head>
<body class="home blog">

<header class="site-header">
<div class="container">
<h1 class="site-title"><a href="<?php echo $siteUrl; ?>/"><?php echo $siteName; ?></a></h1>
<p class="site-description"><?php echo $taglineEsc; ?></p>
</div>
</header>

<nav class="site-nav">
<ul>
<li><a href="<?php echo $siteUrl; ?>/">Home</a></li>
<li><a href="<?php echo $siteUrl; ?>/services/"><?php echo $navServices; ?></a></li>
<li><a href="<?php echo $siteUrl; ?>/about/"><?php echo $navAbout; ?></a></li>
<li><a href="<?php echo $siteUrl; ?>/blog/"><?php echo $navBlog; ?></a></li>
<li><a href="<?php echo $siteUrl; ?>/contact/"><?php echo $navContact; ?></a></li>
</ul>
</nav>

<div class="site-content">
<main class="main-content">

<?php if (!empty($comment_notice) && !empty($message)): ?>
<div class="notice"><?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?></div>
<?php endif; ?>

<?php if (!empty($contact_success)): ?>
<div class="contact-success"><?php echo htmlspecialchars($contact_message ?? '', ENT_QUOTES, 'UTF-8'); ?></div>
<?php endif; ?>

<?php if (!empty($is_search_page)): ?>
<h2 class="search-results">Search Results for: <?php echo $search_term ?? ''; ?></h2>
<div class="search-form">
<form method="get" action="<?php echo $siteUrl; ?>/">
<input type="search" name="s" value="<?php echo $search_term ?? ''; ?>" placeholder="Search &hellip;">
<button type="submit">Search</button>
</form>
</div>
<?php if (!empty($search_results)): ?>
<?php foreach ($search_results as $result): ?>
<article class="post">
<h2 class="post-title"><a href="<?php echo htmlspecialchars($result['url'], ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars($result['title'], ENT_QUOTES, 'UTF-8'); ?></a></h2>
<div class="post-content"><p><?php echo htmlspecialchars($result['excerpt'], ENT_QUOTES, 'UTF-8'); ?></p></div>
</article>
<?php endforeach; ?>
<?php else: ?>
<article class="post"><div class="post-content"><p>Sorry, but nothing matched your search terms. Please try again with some different keywords.</p></div></article>
<?php endif; ?>

<?php elseif (!empty($is_contact_page) && !empty($show_contact_form)): ?>
<article class="post">
<h2 class="post-title">Contact Us</h2>
<div class="post-content">
<form method="post" action="<?php echo $siteUrl; ?>/contact/">
<p><label>Your Name<br><input type="text" name="your-name" size="40"></label></p>
<p><label>Your Email<br><input type="email" name="your-email" size="40"></label></p>
<p><label>Subject<br><input type="text" name="your-subject" size="40"></label></p>
<p><label>Your Message<br><textarea name="your-message" cols="40" rows="10"></textarea></label></p>
<p><input type="submit" value="Send" class="read-more"></p>
</form>
</div>
</article>

<?php elseif (!empty($is_author_page)): ?>
<h2>Author: <?php echo htmlspecialchars($author_name ?? 'admin', ENT_QUOTES, 'UTF-8'); ?></h2>
<?php $authorArticles = array_filter($fallbackArticles, fn($a) => $a['author'] === ($author_name ?? 'admin')); ?>
<?php foreach (($authorArticles ?: [$fallbackArticles[0]]) as $fa): ?>
<article class="post">
<h2 class="post-title"><a href="<?php echo $fa['url']; ?>"><?php echo $fa['title']; ?></a></h2>
<div class="post-meta">Posted on <?php echo $fa['date']; ?> by <?php echo htmlspecialchars($author_name ?? 'admin', ENT_QUOTES, 'UTF-8'); ?></div>
<div class="post-content"><p><?php echo $fa['excerpt']; ?></p></div>
<a href="<?php echo $fa['url']; ?>" class="read-more">Continue reading &raquo;</a>
</article>
<?php endforeach; ?>

<?php else: ?>

<?php if (!empty($generated_posts)): ?>
<?php foreach ($generated_posts as $gp): ?>
<article class="post">
<h2 class="post-title"><a href="<?php echo htmlspecialchars($gp['url'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars($gp['title'] ?? '', ENT_QUOTES, 'UTF-8'); ?></a></h2>
<div class="post-meta">Posted on <?php echo date('F j, Y', strtotime($gp['published_date'] ?? 'now')); ?> by <a href="<?php echo $siteUrl; ?>/author/<?php echo urlencode(strtolower($gp['author'] ?? 'admin')); ?>/"><?php echo htmlspecialchars($gp['author'] ?? 'admin', ENT_QUOTES, 'UTF-8'); ?></a> &mdash; <a href="<?php echo htmlspecialchars($gp['url'] ?? '', ENT_QUOTES, 'UTF-8'); ?>#respond">Leave a comment</a></div>
<div class="post-content">
<p><?php echo htmlspecialchars($gp['excerpt'] ?? '', ENT_QUOTES, 'UTF-8'); ?></p>
</div>
<a href="<?php echo htmlspecialchars($gp['url'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" class="read-more">Continue reading &raquo;</a>
</article>
<?php endforeach; ?>
<?php else: ?>

<?php foreach ($fallbackArticles as $fa): ?>
<article class="post">
<h2 class="post-title"><a href="<?php echo $fa['url']; ?>"><?php echo $fa['title']; ?></a></h2>
<div class="post-meta">Posted on <?php echo $fa['date']; ?> by <a href="<?php echo $siteUrl; ?>/author/<?php echo urlencode($fa['author']); ?>/"><?php echo htmlspecialchars($fa['author'], ENT_QUOTES, 'UTF-8'); ?></a> &mdash; <a href="<?php echo $fa['url']; ?>#respond">Leave a comment</a></div>
<div class="post-content">
<p><?php echo $fa['excerpt']; ?></p>
</div>
<a href="<?php echo $fa['url']; ?>" class="read-more">Continue reading &raquo;</a>
</article>
<?php endforeach; ?>
<?php endif; ?>

<!-- Comment Form -->
<div class="comment-form-area">
<h3>Leave a Reply</h3>
<form action="<?php echo $siteUrl; ?>/wp-comments-post.php" method="post">
<p><label>Comment<br><textarea name="comment" cols="45" rows="8" required></textarea></label></p>
<p><label>Name<br><input type="text" name="author" size="30" required></label></p>
<p><label>Email<br><input type="email" name="email" size="30" required></label></p>
<p><label>Website<br><input type="url" name="url" size="30"></label></p>
<input type="hidden" name="comment_post_ID" value="1">
<input type="hidden" name="comment_parent" value="0">
<div style="position:absolute;left:-9999px;top:-9999px"><label>Leave this field empty<input type="text" name="hp_field" value="" tabindex="-1" autocomplete="off"></label></div>
<p><input type="submit" value="Post Comment" class="submit-btn"></p>
</form>
</div>

<?php endif; ?>

</main>

<aside class="sidebar">
<div class="widget">
<h3 class="widget-title">Search</h3>
<form method="get" action="<?php echo $siteUrl; ?>/">
<input type="search" name="s" placeholder="Search &hellip;" style="width:100%;padding:8px;border:1px solid #ddd;font-size:14px">
</form>
</div>

<div class="widget">
<h3 class="widget-title">Recent Posts</h3>
<ul>
<?php if (!empty($generated_posts)): ?>
    <?php foreach (array_slice($generated_posts, 0, 5) as $rp): ?>
    <li><a href="<?php echo htmlspecialchars($rp['url'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars($rp['title'] ?? '', ENT_QUOTES, 'UTF-8'); ?></a></li>
    <?php endforeach; ?>
<?php else: ?>
    <?php foreach ($fallbackArticles as $fa): ?>
    <li><a href="<?php echo $fa['url']; ?>"><?php echo $fa['title']; ?></a></li>
    <?php endforeach; ?>
<?php endif; ?>
</ul>
</div>

<div class="widget">
<h3 class="widget-title">Recent Comments</h3>
<ul>
<li>A WordPress Commenter on <a href="<?php echo $fallbackArticles[0]['url']; ?>#comment-1"><?php echo $fallbackArticles[0]['title']; ?></a></li>
</ul>
</div>

<div class="widget">
<h3 class="widget-title">Archives</h3>
<ul>
<li><a href="<?php echo $siteUrl; ?>/2024/09/">September 2024</a></li>
<li><a href="<?php echo $siteUrl; ?>/2024/08/">August 2024</a></li>
<li><a href="<?php echo $siteUrl; ?>/2024/07/">July 2024</a></li>
<li><a href="<?php echo $siteUrl; ?>/2024/06/">June 2024</a></li>
<li><a href="<?php echo $siteUrl; ?>/2024/05/">May 2024</a></li>
</ul>
</div>

<div class="widget">
<h3 class="widget-title">Categories</h3>
<ul>
<?php foreach ($fallbackCategories as $cat): ?>
<li><a href="<?php echo $siteUrl; ?>/category/<?php echo urlencode(strtolower(str_replace(' ', '-', $cat))); ?>/"><?php echo htmlspecialchars($cat, ENT_QUOTES, 'UTF-8'); ?></a></li>
<?php endforeach; ?>
</ul>
</div>

<div class="widget">
<h3 class="widget-title">Meta</h3>
<ul>
<li><a href="<?php echo $siteUrl; ?>/wp-login.php">Log in</a></li>
<li><a href="<?php echo $siteUrl; ?>/feed/">Entries feed</a></li>
<li><a href="<?php echo $siteUrl; ?>/comments/feed/">Comments feed</a></li>
<li><a href="https://wordpress.org/">WordPress.org</a></li>
</ul>
</div>
</aside>
</div>

<footer class="site-footer">
<p>Proudly powered by <a href="https://wordpress.org/">WordPress</a>.</p>
<p>&copy; <?php echo $year; ?> <?php echo $siteName; ?>. All rights reserved.</p>
</footer>

<script src='<?php echo $siteUrl; ?>/wp-includes/js/jquery/jquery.min.js?ver=3.7.1' id='jquery-core-js'></script>
<script src='<?php echo $siteUrl; ?>/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1' id='jquery-migrate-js'></script>
<script src='<?php echo $siteUrl; ?>/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.8.4' id='contact-form-7-js'></script>
<script src='<?php echo $siteUrl; ?>/wp-includes/js/wp-embed.min.js?ver=<?php echo $version; ?>' id='wp-embed-js'></script>
</body>
</html>
