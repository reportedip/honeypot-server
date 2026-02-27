<?php
/**
 * WordPress homepage template.
 *
 * Variables: $site_name, $site_url, $wp_version, $tagline, $theme,
 *            $language, $request_uri
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
$year = date('Y');
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
<li><a href="<?php echo $siteUrl; ?>/about/">About</a></li>
<li><a href="<?php echo $siteUrl; ?>/blog/">Blog</a></li>
<li><a href="<?php echo $siteUrl; ?>/contact/">Contact</a></li>
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
<article class="post">
<h2 class="post-title"><a href="<?php echo $siteUrl; ?>/hello-world/">Hello world!</a></h2>
<div class="post-meta">Posted on January 15, 2024 by <?php echo htmlspecialchars($author_name ?? 'admin', ENT_QUOTES, 'UTF-8'); ?></div>
<div class="post-content"><p>Welcome to our site. This is our first post. Edit or delete it, then start writing!</p></div>
<a href="<?php echo $siteUrl; ?>/hello-world/" class="read-more">Continue reading &raquo;</a>
</article>

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

<article class="post">
<h2 class="post-title"><a href="<?php echo $siteUrl; ?>/hello-world/">Hello world!</a></h2>
<div class="post-meta">Posted on January 15, 2024 by <a href="<?php echo $siteUrl; ?>/author/admin/">admin</a> &mdash; <a href="<?php echo $siteUrl; ?>/hello-world/#respond">1 Comment</a></div>
<div class="post-content">
<p>Welcome to our site. This is our first post. Edit or delete it, then start writing!</p>
</div>
<a href="<?php echo $siteUrl; ?>/hello-world/" class="read-more">Continue reading &raquo;</a>
</article>

<article class="post">
<h2 class="post-title"><a href="<?php echo $siteUrl; ?>/getting-started/">Getting Started with Our Services</a></h2>
<div class="post-meta">Posted on February 3, 2024 by <a href="<?php echo $siteUrl; ?>/author/admin/">admin</a> &mdash; <a href="<?php echo $siteUrl; ?>/getting-started/#respond">Leave a comment</a></div>
<div class="post-content">
<p>We are excited to announce the launch of our new website. Stay tuned for updates about our products and services. We have been working hard to bring you the best experience possible.</p>
</div>
<a href="<?php echo $siteUrl; ?>/getting-started/" class="read-more">Continue reading &raquo;</a>
</article>

<article class="post">
<h2 class="post-title"><a href="<?php echo $siteUrl; ?>/company-news/">Latest Company News and Updates</a></h2>
<div class="post-meta">Posted on March 10, 2024 by <a href="<?php echo $siteUrl; ?>/author/editor/">editor</a> &mdash; <a href="<?php echo $siteUrl; ?>/company-news/#respond">Leave a comment</a></div>
<div class="post-content">
<p>Here at our company, we are always striving to improve. This month we have several exciting announcements to share with our community. Read on to learn more about our upcoming plans.</p>
</div>
<a href="<?php echo $siteUrl; ?>/company-news/" class="read-more">Continue reading &raquo;</a>
</article>
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
    <li><a href="<?php echo $siteUrl; ?>/company-news/">Latest Company News and Updates</a></li>
    <li><a href="<?php echo $siteUrl; ?>/getting-started/">Getting Started with Our Services</a></li>
    <li><a href="<?php echo $siteUrl; ?>/hello-world/">Hello world!</a></li>
<?php endif; ?>
</ul>
</div>

<div class="widget">
<h3 class="widget-title">Recent Comments</h3>
<ul>
<li>A WordPress Commenter on <a href="<?php echo $siteUrl; ?>/hello-world/#comment-1">Hello world!</a></li>
</ul>
</div>

<div class="widget">
<h3 class="widget-title">Archives</h3>
<ul>
<li><a href="<?php echo $siteUrl; ?>/2024/03/">March 2024</a></li>
<li><a href="<?php echo $siteUrl; ?>/2024/02/">February 2024</a></li>
<li><a href="<?php echo $siteUrl; ?>/2024/01/">January 2024</a></li>
</ul>
</div>

<div class="widget">
<h3 class="widget-title">Categories</h3>
<ul>
<li><a href="<?php echo $siteUrl; ?>/category/uncategorized/">Uncategorized</a></li>
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

</body>
</html>
