<?php
/**
 * WordPress single post template for AI-generated content.
 *
 * Variables: $site_name, $site_url, $wp_version, $tagline, $theme,
 *            $language, $post, $recent_posts, $request_uri
 */

$siteUrl = htmlspecialchars($site_url ?? '', ENT_QUOTES, 'UTF-8');
$siteName = htmlspecialchars($site_name ?? 'My WordPress Site', ENT_QUOTES, 'UTF-8');
$taglineEsc = htmlspecialchars($tagline ?? 'Just another WordPress site', ENT_QUOTES, 'UTF-8');
$version = htmlspecialchars($wp_version ?? '6.4.2', ENT_QUOTES, 'UTF-8');
$year = date('Y');

$postTitle = htmlspecialchars($post['title'] ?? '', ENT_QUOTES, 'UTF-8');
$postAuthor = htmlspecialchars($post['author'] ?? 'admin', ENT_QUOTES, 'UTF-8');
$postCategory = htmlspecialchars($post['category'] ?? 'Uncategorized', ENT_QUOTES, 'UTF-8');
$postDate = date('F j, Y', strtotime($post['published_date'] ?? 'now'));
$postContent = $post['content'] ?? '';
$metaDesc = htmlspecialchars($post['meta_description'] ?? $post['excerpt'] ?? '', ENT_QUOTES, 'UTF-8');
$canonicalUrl = htmlspecialchars($post['url'] ?? '', ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars($language ?? 'en-US', ENT_QUOTES, 'UTF-8') ?>">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="WordPress <?= $version ?>">
<meta name="description" content="<?= $metaDesc ?>">
<meta property="og:title" content="<?= $postTitle ?>">
<meta property="og:description" content="<?= $metaDesc ?>">
<meta property="og:type" content="article">
<link rel="canonical" href="<?= $canonicalUrl ?>">
<title><?= $postTitle ?> &#8211; <?= $siteName ?></title>
<link rel="alternate" type="application/rss+xml" title="<?= $siteName ?> &raquo; Feed" href="<?= $siteUrl ?>/feed/">
<link rel="pingback" href="<?= $siteUrl ?>/xmlrpc.php">
<style type="text/css">
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif;font-size:16px;line-height:1.7;color:#333;background:#f0f0f0}
a{color:#0073aa;text-decoration:none}a:hover{color:#005177;text-decoration:underline}
.site-header{background:#fff;border-bottom:1px solid #ddd;padding:30px 0}
.site-header .container{max-width:1100px;margin:0 auto;padding:0 20px}
.site-title{font-size:28px;font-weight:700;margin:0}
.site-title a{color:#333;text-decoration:none}
.site-description{color:#777;font-size:14px;margin-top:4px}
.site-nav{background:#23282d;padding:0}
.site-nav ul{list-style:none;max-width:1100px;margin:0 auto;padding:0 20px;display:flex}
.site-nav a{display:block;padding:12px 18px;color:#eee;font-size:14px;text-decoration:none}
.site-nav a:hover{background:#32373c;color:#fff}
.site-content{max-width:1100px;margin:30px auto;padding:0 20px;display:flex;gap:30px}
.main-content{flex:1;min-width:0}
.sidebar{width:300px;flex-shrink:0}
.post{background:#fff;padding:30px;margin-bottom:30px;border:1px solid #ddd}
.post-title{font-size:28px;margin-bottom:10px;line-height:1.3}
.post-meta{color:#777;font-size:13px;margin-bottom:20px;padding-bottom:15px;border-bottom:1px solid #eee}
.post-content p{margin-bottom:15px}
.post-content h2,.post-content h3{margin:20px 0 10px}
.widget{background:#fff;padding:20px;margin-bottom:20px;border:1px solid #ddd}
.widget-title{font-size:16px;font-weight:700;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #eee}
.widget ul{list-style:none;padding:0}.widget li{padding:5px 0;border-bottom:1px solid #f5f5f5}
.widget li:last-child{border-bottom:none}
.comment-form-area{background:#fff;padding:30px;border:1px solid #ddd;margin-bottom:30px}
.comment-form-area h3{margin-bottom:15px;font-size:20px}
.comment-form-area input[type="text"],.comment-form-area input[type="email"],.comment-form-area input[type="url"],.comment-form-area textarea{width:100%;padding:8px 12px;border:1px solid #ddd;font-size:14px;margin-bottom:10px;font-family:inherit}
.comment-form-area textarea{height:120px;resize:vertical}
.comment-form-area .submit-btn{background:#0073aa;color:#fff;border:none;padding:10px 20px;cursor:pointer;font-size:14px;border-radius:3px}
.site-footer{background:#23282d;color:#aaa;text-align:center;padding:20px;font-size:13px;margin-top:40px}
.site-footer a{color:#ccc}
.breadcrumb{font-size:13px;color:#777;margin-bottom:20px}
.breadcrumb a{color:#0073aa}
@media(max-width:768px){.site-content{flex-direction:column}.sidebar{width:100%}}
</style>
</head>
<body class="single single-post">

<header class="site-header">
<div class="container">
<h1 class="site-title"><a href="<?= $siteUrl ?>/"><?= $siteName ?></a></h1>
<p class="site-description"><?= $taglineEsc ?></p>
</div>
</header>

<nav class="site-nav">
<ul>
<li><a href="<?= $siteUrl ?>/">Home</a></li>
<li><a href="<?= $siteUrl ?>/about/">About</a></li>
<li><a href="<?= $siteUrl ?>/blog/">Blog</a></li>
<li><a href="<?= $siteUrl ?>/contact/">Contact</a></li>
</ul>
</nav>

<div class="site-content">
<main class="main-content">

<div class="breadcrumb">
<a href="<?= $siteUrl ?>/">Home</a> &raquo; <a href="<?= $siteUrl ?>/category/<?= strtolower(str_replace(' ', '-', $postCategory)) ?>/"><?= $postCategory ?></a> &raquo; <?= $postTitle ?>
</div>

<article class="post">
<h1 class="post-title"><?= $postTitle ?></h1>
<div class="post-meta">
Posted on <?= $postDate ?> by <a href="<?= $siteUrl ?>/author/<?= urlencode(strtolower($post['author'] ?? 'admin')) ?>/"><?= $postAuthor ?></a>
&mdash; Category: <a href="<?= $siteUrl ?>/category/<?= urlencode(strtolower(str_replace(' ', '-', $postCategory))) ?>/"><?= $postCategory ?></a>
</div>
<div class="post-content">
<?= $postContent ?>
</div>
</article>

<div class="comment-form-area">
<h3>Leave a Reply</h3>
<form action="<?= $siteUrl ?>/wp-comments-post.php" method="post">
<p><label>Comment<br><textarea name="comment" cols="45" rows="8" required></textarea></label></p>
<p><label>Name<br><input type="text" name="author" size="30" required></label></p>
<p><label>Email<br><input type="email" name="email" size="30" required></label></p>
<p><label>Website<br><input type="url" name="url" size="30"></label></p>
<input type="hidden" name="comment_post_ID" value="<?= (int)($post['id'] ?? 1) ?>">
<div style="position:absolute;left:-9999px;top:-9999px"><label>Leave this field empty<input type="text" name="hp_field" value="" tabindex="-1" autocomplete="off"></label></div>
<p><input type="submit" value="Post Comment" class="submit-btn"></p>
</form>
</div>

</main>

<aside class="sidebar">
<div class="widget">
<h3 class="widget-title">Search</h3>
<form method="get" action="<?= $siteUrl ?>/">
<input type="search" name="s" placeholder="Search &hellip;" style="width:100%;padding:8px;border:1px solid #ddd;font-size:14px">
</form>
</div>

<div class="widget">
<h3 class="widget-title">Recent Posts</h3>
<ul>
<?php if (!empty($recent_posts)): ?>
    <?php foreach ($recent_posts as $rp): ?>
    <li><a href="<?= htmlspecialchars($rp['url'] ?? '', ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars($rp['title'] ?? '', ENT_QUOTES, 'UTF-8') ?></a></li>
    <?php endforeach; ?>
<?php else: ?>
    <li><a href="<?= $siteUrl ?>/hello-world/">Hello world!</a></li>
<?php endif; ?>
</ul>
</div>

<div class="widget">
<h3 class="widget-title">Categories</h3>
<ul>
<li><a href="<?= $siteUrl ?>/category/uncategorized/">Uncategorized</a></li>
</ul>
</div>

<div class="widget">
<h3 class="widget-title">Meta</h3>
<ul>
<li><a href="<?= $siteUrl ?>/wp-login.php">Log in</a></li>
<li><a href="<?= $siteUrl ?>/feed/">Entries feed</a></li>
<li><a href="https://wordpress.org/">WordPress.org</a></li>
</ul>
</div>
</aside>
</div>

<footer class="site-footer">
<p>Proudly powered by <a href="https://wordpress.org/">WordPress</a>.</p>
<p>&copy; <?= $year ?> <?= $siteName ?>. All rights reserved.</p>
</footer>

</body>
</html>
