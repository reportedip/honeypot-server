<?php
/**
 * Drupal single article template for AI-generated content.
 *
 * Variables: $site_name, $site_url, $drupal_version, $theme, $language,
 *            $post, $recent_posts, $request_uri
 */

$siteUrl = htmlspecialchars($site_url ?? '', ENT_QUOTES, 'UTF-8');
$siteName = htmlspecialchars($site_name ?? 'My Drupal Site', ENT_QUOTES, 'UTF-8');
$version = htmlspecialchars($drupal_version ?? '10.2.2', ENT_QUOTES, 'UTF-8');
$year = date('Y');

$postTitle = htmlspecialchars($post['title'] ?? '', ENT_QUOTES, 'UTF-8');
$postAuthor = htmlspecialchars($post['author'] ?? 'admin', ENT_QUOTES, 'UTF-8');
$postCategory = htmlspecialchars($post['category'] ?? 'Uncategorized', ENT_QUOTES, 'UTF-8');
$postDate = date('D, m/d/Y - H:i', strtotime($post['published_date'] ?? 'now'));
$postContent = $post['content'] ?? '';
$metaDesc = htmlspecialchars($post['meta_description'] ?? $post['excerpt'] ?? '', ENT_QUOTES, 'UTF-8');
$canonicalUrl = htmlspecialchars($post['url'] ?? '', ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars($language ?? 'en', ENT_QUOTES, 'UTF-8') ?>" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="Generator" content="Drupal 10 (https://www.drupal.org)">
<meta name="description" content="<?= $metaDesc ?>">
<meta property="og:title" content="<?= $postTitle ?>">
<meta property="og:description" content="<?= $metaDesc ?>">
<meta property="og:type" content="article">
<link rel="canonical" href="<?= $canonicalUrl ?>">
<title><?= $postTitle ?> | <?= $siteName ?></title>
<style type="text/css">
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:"Source Sans Pro",sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial;font-size:16px;line-height:1.6;color:#232629;background:#e7e4df}
a{color:#003cc5;text-decoration:underline}a:hover{color:#002e9a}
.dialog-off-canvas-main-canvas{display:flex;flex-direction:column;min-height:100vh}
header.site-header{background:#1b1b1b;color:#fff;padding:0}
.site-branding{max-width:1200px;margin:0 auto;padding:16px 20px;display:flex;align-items:center;justify-content:space-between}
.site-branding h1{font-size:24px;font-weight:700;margin:0}
.site-branding h1 a{color:#fff;text-decoration:none}
nav.main-nav{background:#2d2d2d}
nav.main-nav ul{list-style:none;max-width:1200px;margin:0 auto;padding:0 20px;display:flex}
nav.main-nav a{display:block;padding:12px 18px;color:#d4d4d8;text-decoration:none;font-size:15px}
nav.main-nav a:hover{background:#3d3d3d;color:#fff}
.main-content-wrapper{max-width:1200px;margin:30px auto;padding:0 20px;display:flex;gap:30px;flex:1}
main.main-content{flex:1;min-width:0}
aside.sidebar{width:280px;flex-shrink:0}
.node-full{background:#fff;padding:30px;margin-bottom:25px;border:1px solid #d3d4d9;border-radius:4px}
.node-full h1{font-size:26px;margin-bottom:10px;font-weight:700;color:#232629}
.node-full .node-meta{color:#57575d;font-size:13px;margin-bottom:20px;padding-bottom:15px;border-bottom:1px solid #eee}
.node-full .node-content p{margin-bottom:12px}
.node-full .node-content h2,.node-full .node-content h3{margin:20px 0 10px}
.node-full .field-tags{margin-top:20px;padding-top:15px;border-top:1px solid #eee;font-size:13px;color:#57575d}
.node-full .field-tags a{margin-right:8px}
.block{background:#fff;padding:20px;margin-bottom:20px;border:1px solid #d3d4d9;border-radius:4px}
.block h2{font-size:16px;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #eee}
.block ul{list-style:none;padding:0}
.block li{padding:5px 0;border-bottom:1px solid #f5f5f5;font-size:14px}
.block li:last-child{border-bottom:none}
footer.site-footer{background:#1b1b1b;color:#929296;text-align:center;padding:20px;font-size:13px;margin-top:auto}
footer.site-footer a{color:#55b3ea}
.breadcrumb{font-size:13px;color:#57575d;margin-bottom:20px}
.breadcrumb a{color:#003cc5}
@media(max-width:768px){.main-content-wrapper{flex-direction:column}aside.sidebar{width:100%}}
</style>
</head>
<body>
<div class="dialog-off-canvas-main-canvas">

<header class="site-header">
<div class="site-branding">
<h1><a href="<?= $siteUrl ?>/"><?= $siteName ?></a></h1>
<div style="color:#929296;font-size:13px">Powered by Drupal</div>
</div>
</header>

<nav class="main-nav">
<ul>
<li><a href="<?= $siteUrl ?>/">Home</a></li>
<li><a href="<?= $siteUrl ?>/about">About</a></li>
<li><a href="<?= $siteUrl ?>/articles">Articles</a></li>
<li><a href="<?= $siteUrl ?>/contact">Contact</a></li>
</ul>
</nav>

<div class="main-content-wrapper">
<main class="main-content">

<div class="breadcrumb">
<a href="<?= $siteUrl ?>/">Home</a> &raquo; <?= $postTitle ?>
</div>

<article class="node-full">
<h1><?= $postTitle ?></h1>
<div class="node-meta">
Submitted by <a href="<?= $siteUrl ?>/user/1"><?= $postAuthor ?></a> on <?= $postDate ?>
</div>
<div class="node-content">
<?= $postContent ?>
</div>
<div class="field-tags">
Tags: <a href="<?= $siteUrl ?>/taxonomy/term/1"><?= $postCategory ?></a>
</div>
</article>

</main>

<aside class="sidebar">
<div class="block">
<h2>Search</h2>
<form method="get" action="<?= $siteUrl ?>/search">
<input type="search" name="keys" placeholder="Search" style="width:100%;padding:8px;border:1px solid #8e929c;font-size:14px;border-radius:4px">
</form>
</div>

<div class="block">
<h2>Recent content</h2>
<ul>
<?php if (!empty($recent_posts)): ?>
    <?php foreach ($recent_posts as $rp): ?>
    <li><a href="<?= htmlspecialchars($rp['url'] ?? '', ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars($rp['title'] ?? '', ENT_QUOTES, 'UTF-8') ?></a></li>
    <?php endforeach; ?>
<?php else: ?>
    <li><a href="<?= $siteUrl ?>/node/1">Our First Article</a></li>
<?php endif; ?>
</ul>
</div>

<div class="block">
<h2>User login</h2>
<form method="post" action="<?= $siteUrl ?>/user/login">
<div style="margin-bottom:8px"><label style="font-size:13px;display:block">Username</label><input type="text" name="name" style="width:100%;padding:6px;border:1px solid #8e929c;border-radius:3px;font-size:13px"></div>
<div style="margin-bottom:8px"><label style="font-size:13px;display:block">Password</label><input type="password" name="pass" style="width:100%;padding:6px;border:1px solid #8e929c;border-radius:3px;font-size:13px"></div>
<button type="submit" style="padding:6px 14px;background:#003cc5;color:#fff;border:none;border-radius:3px;cursor:pointer;font-size:13px">Log in</button>
</form>
</div>
</aside>
</div>

<footer class="site-footer">
<p>&copy; <?= $year ?> <?= $siteName ?>. All rights reserved.</p>
<p>Powered by <a href="https://www.drupal.org">Drupal</a></p>
</footer>

</div>
</body>
</html>
