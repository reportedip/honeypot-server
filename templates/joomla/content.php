<?php
/**
 * Joomla single article template for AI-generated content.
 *
 * Variables: $site_name, $site_url, $joomla_version, $template, $language,
 *            $post, $recent_posts, $request_uri
 */

$siteUrl = htmlspecialchars($site_url ?? '', ENT_QUOTES, 'UTF-8');
$siteName = htmlspecialchars($site_name ?? 'My Joomla Site', ENT_QUOTES, 'UTF-8');
$version = htmlspecialchars($joomla_version ?? '4.4.2', ENT_QUOTES, 'UTF-8');
$year = date('Y');

$postTitle = htmlspecialchars($post['title'] ?? '', ENT_QUOTES, 'UTF-8');
$postAuthor = htmlspecialchars($post['author'] ?? 'Super User', ENT_QUOTES, 'UTF-8');
$postCategory = htmlspecialchars($post['category'] ?? 'Uncategorized', ENT_QUOTES, 'UTF-8');
$postDate = date('d F Y', strtotime($post['published_date'] ?? 'now'));
$postContent = $post['content'] ?? '';
$metaDesc = htmlspecialchars($post['meta_description'] ?? $post['excerpt'] ?? '', ENT_QUOTES, 'UTF-8');
$canonicalUrl = htmlspecialchars($post['url'] ?? '', ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars($language ?? 'en-GB', ENT_QUOTES, 'UTF-8') ?>" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="Joomla! - Open Source Content Management - Version <?= $version ?>">
<meta name="description" content="<?= $metaDesc ?>">
<meta property="og:title" content="<?= $postTitle ?>">
<meta property="og:description" content="<?= $metaDesc ?>">
<meta property="og:type" content="article">
<link rel="canonical" href="<?= $canonicalUrl ?>">
<title><?= $postTitle ?> - <?= $siteName ?></title>
<style type="text/css">
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:"Roboto",-apple-system,BlinkMacSystemFont,"Segoe UI","Helvetica Neue",Arial,sans-serif;font-size:16px;line-height:1.6;color:#212529;background:#f4f6f7}
a{color:#457b9d;text-decoration:none}a:hover{color:#1d3557;text-decoration:underline}
.header-wrapper{background:#1d3557;color:#fff}
.container{max-width:1200px;margin:0 auto;padding:0 20px}
.site-header{padding:20px 0;display:flex;align-items:center;justify-content:space-between}
.site-header h1{font-size:26px;font-weight:700;margin:0}
.site-header h1 a{color:#fff;text-decoration:none}
nav.top-nav{background:#14253d;padding:0}
nav.top-nav ul{list-style:none;display:flex;max-width:1200px;margin:0 auto;padding:0 20px}
nav.top-nav a{display:block;padding:12px 18px;color:#a8dadc;font-size:14px;text-decoration:none}
nav.top-nav a:hover{background:#1d3557;color:#fff}
.main-wrapper{max-width:1200px;margin:30px auto;padding:0 20px;display:flex;gap:30px}
.main-content{flex:1;min-width:0}
.sidebar{width:280px;flex-shrink:0}
.item-page-full{background:#fff;padding:30px;margin-bottom:25px;border:1px solid #dee2e6;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,0.04)}
.item-page-full h1{font-size:26px;margin-bottom:10px;font-weight:600;color:#1d3557}
.item-page-full .article-info{color:#6c757d;font-size:13px;margin-bottom:20px;padding-bottom:15px;border-bottom:1px solid #eee}
.item-page-full .article-info span{margin-right:12px}
.item-page-full .article-content p{margin-bottom:12px}
.item-page-full .article-content h2,.item-page-full .article-content h3{margin:20px 0 10px;color:#1d3557}
.module{background:#fff;padding:20px;margin-bottom:20px;border:1px solid #dee2e6;border-radius:4px}
.module h3{font-size:15px;font-weight:600;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #eee;color:#1d3557}
.module ul{list-style:none;padding:0}
.module li{padding:5px 0;border-bottom:1px solid #f5f5f5;font-size:14px}
.module li:last-child{border-bottom:none}
.module li a{color:#457b9d}
.site-footer{background:#1d3557;color:#a8dadc;text-align:center;padding:20px;font-size:13px;margin-top:40px}
.site-footer a{color:#fff}
.breadcrumb{font-size:13px;color:#6c757d;margin-bottom:20px}
.breadcrumb a{color:#457b9d}
@media(max-width:768px){.main-wrapper{flex-direction:column}.sidebar{width:100%}}
</style>
</head>
<body class="site com_content">

<div class="header-wrapper">
<div class="container">
<header class="site-header">
<h1><a href="<?= $siteUrl ?>/"><?= $siteName ?></a></h1>
</header>
</div>
</div>

<nav class="top-nav">
<ul class="container" style="padding:0 20px">
<li><a href="<?= $siteUrl ?>/">Home</a></li>
<li><a href="<?= $siteUrl ?>/about">About Us</a></li>
<li><a href="<?= $siteUrl ?>/services">Services</a></li>
<li><a href="<?= $siteUrl ?>/blog">Blog</a></li>
<li><a href="<?= $siteUrl ?>/contact">Contact</a></li>
</ul>
</nav>

<div class="main-wrapper">
<main class="main-content">

<div class="breadcrumb">
<a href="<?= $siteUrl ?>/">Home</a> &raquo; <a href="<?= $siteUrl ?>/blog">Blog</a> &raquo; <?= $postTitle ?>
</div>

<article class="item-page-full">
<h1><?= $postTitle ?></h1>
<div class="article-info">
<span>Written by <strong><?= $postAuthor ?></strong></span>
<span>Category: <a href="<?= $siteUrl ?>/category/<?= urlencode(strtolower(str_replace(' ', '-', $postCategory))) ?>"><?= $postCategory ?></a></span>
<span>Published: <?= $postDate ?></span>
</div>
<div class="article-content">
<?= $postContent ?>
</div>
</article>

</main>

<aside class="sidebar">
<div class="module">
<h3>Main Menu</h3>
<ul>
<li><a href="<?= $siteUrl ?>/">Home</a></li>
<li><a href="<?= $siteUrl ?>/about">About Us</a></li>
<li><a href="<?= $siteUrl ?>/services">Services</a></li>
<li><a href="<?= $siteUrl ?>/blog">Blog</a></li>
<li><a href="<?= $siteUrl ?>/contact">Contact</a></li>
</ul>
</div>

<div class="module">
<h3>Latest Articles</h3>
<ul>
<?php if (!empty($recent_posts)): ?>
    <?php foreach ($recent_posts as $rp): ?>
    <li><a href="<?= htmlspecialchars($rp['url'] ?? '', ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars($rp['title'] ?? '', ENT_QUOTES, 'UTF-8') ?></a></li>
    <?php endforeach; ?>
<?php else: ?>
    <li><a href="<?= $siteUrl ?>/welcome">Welcome to <?= $siteName ?></a></li>
<?php endif; ?>
</ul>
</div>

<div class="module">
<h3>Login Form</h3>
<form method="post" action="<?= $siteUrl ?>/index.php?option=com_users&task=user.login">
<div style="margin-bottom:8px"><label style="font-size:13px;display:block">Username</label><input type="text" name="username" style="width:100%;padding:6px;border:1px solid #ced4da;border-radius:3px;font-size:13px"></div>
<div style="margin-bottom:8px"><label style="font-size:13px;display:block">Password</label><input type="password" name="passwd" style="width:100%;padding:6px;border:1px solid #ced4da;border-radius:3px;font-size:13px"></div>
<button type="submit" style="padding:6px 14px;background:#457b9d;color:#fff;border:none;border-radius:3px;cursor:pointer;font-size:13px;width:100%">Log in</button>
</form>
</div>
</aside>
</div>

<footer class="site-footer">
<p>&copy; <?= $year ?> <?= $siteName ?>. All Rights Reserved.</p>
<p><a href="https://www.joomla.org">Joomla!</a> is Free Software released under the <a href="https://www.gnu.org/licenses/gpl-2.0.html">GNU General Public License</a>.</p>
</footer>

</body>
</html>
