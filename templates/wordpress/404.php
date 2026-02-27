<?php
/**
 * WordPress 404 page template.
 *
 * Variables: $site_name, $site_url, $wp_version, $request_path, $language
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
<title>Page not found &#8211; <?php echo $siteName; ?></title>
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
.error-404{background:#fff;padding:40px 30px;border:1px solid #ddd}
.error-404 h1{font-size:28px;margin-bottom:15px}
.error-404 p{margin-bottom:15px;color:#555}
.error-404 .search-form{margin:20px 0}
.error-404 .search-form input[type="search"]{padding:8px 12px;width:280px;border:1px solid #ddd;font-size:14px}
.error-404 .search-form button{padding:8px 16px;background:#0073aa;color:#fff;border:none;cursor:pointer;font-size:14px;border-radius:3px}
.widget{background:#fff;padding:20px;margin-bottom:20px;border:1px solid #ddd}
.widget-title{font-size:16px;font-weight:700;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #eee}
.widget ul{list-style:none;padding:0}
.widget li{padding:5px 0;border-bottom:1px solid #f5f5f5}
.widget li:last-child{border-bottom:none}
.site-footer{background:#23282d;color:#aaa;text-align:center;padding:20px;font-size:13px;margin-top:40px}
.site-footer a{color:#ccc}
@media(max-width:768px){.site-content{flex-direction:column}.sidebar{width:100%}}
</style>
</head>
<body class="error404">

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
<div class="error-404">
<h1>Oops! That page can&rsquo;t be found.</h1>
<p>It looks like nothing was found at this location. Maybe try a search?</p>
<div class="search-form">
<form method="get" action="<?php echo $siteUrl; ?>/">
<input type="search" name="s" placeholder="Search &hellip;">
<button type="submit">Search</button>
</form>
</div>
<h2 style="font-size:18px;margin:25px 0 10px">Recent Posts</h2>
<ul style="list-style:disc;padding-left:20px">
<li><a href="<?php echo $siteUrl; ?>/company-news/">Latest Company News and Updates</a></li>
<li><a href="<?php echo $siteUrl; ?>/getting-started/">Getting Started with Our Services</a></li>
<li><a href="<?php echo $siteUrl; ?>/hello-world/">Hello world!</a></li>
</ul>
</div>
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
<li><a href="<?php echo $siteUrl; ?>/company-news/">Latest Company News and Updates</a></li>
<li><a href="<?php echo $siteUrl; ?>/getting-started/">Getting Started with Our Services</a></li>
<li><a href="<?php echo $siteUrl; ?>/hello-world/">Hello world!</a></li>
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
</aside>
</div>

<footer class="site-footer">
<p>Proudly powered by <a href="https://wordpress.org/">WordPress</a>.</p>
<p>&copy; <?php echo $year; ?> <?php echo $siteName; ?>. All rights reserved.</p>
</footer>

</body>
</html>
