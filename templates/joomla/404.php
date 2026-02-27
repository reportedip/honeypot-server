<?php
/**
 * Joomla 404 error page template.
 *
 * Variables: $site_name, $site_url, $joomla_version, $language
 */
$siteUrl = htmlspecialchars($site_url ?? '', ENT_QUOTES, 'UTF-8');
$siteName = htmlspecialchars($site_name ?? 'My Joomla Site', ENT_QUOTES, 'UTF-8');
$version = htmlspecialchars($joomla_version ?? '4.4.2', ENT_QUOTES, 'UTF-8');
$year = date('Y');
?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars($language ?? 'en-GB', ENT_QUOTES, 'UTF-8') ?>" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="Joomla! - Open Source Content Management - Version <?= $version ?>">
<title>404 - Article not found - <?= $siteName ?></title>
<style type="text/css">
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:"Roboto",-apple-system,BlinkMacSystemFont,"Segoe UI","Helvetica Neue",Arial,sans-serif;font-size:16px;line-height:1.6;color:#212529;background:#f4f6f7}
a{color:#457b9d;text-decoration:none}a:hover{color:#1d3557;text-decoration:underline}
.header-wrapper{background:#1d3557;color:#fff}
.container{max-width:1200px;margin:0 auto;padding:0 20px}
.site-header{padding:20px 0;display:flex;align-items:center;justify-content:space-between}
.site-header h1{font-size:26px;font-weight:700;margin:0}
.site-header h1 a{color:#fff;text-decoration:none}
.site-header .header-search{display:flex;gap:4px}
.site-header .header-search input{padding:6px 12px;border:none;border-radius:3px;font-size:13px;width:180px}
.site-header .header-search button{padding:6px 12px;background:#457b9d;color:#fff;border:none;border-radius:3px;cursor:pointer;font-size:13px}
nav.top-nav{background:#14253d;padding:0}
nav.top-nav ul{list-style:none;display:flex;max-width:1200px;margin:0 auto;padding:0 20px}
nav.top-nav a{display:block;padding:12px 18px;color:#a8dadc;font-size:14px;text-decoration:none}
nav.top-nav a:hover{background:#1d3557;color:#fff}
.main-wrapper{max-width:1200px;margin:30px auto;padding:0 20px;display:flex;gap:30px}
.main-content{flex:1;min-width:0}
.sidebar{width:280px;flex-shrink:0}
.error-page{background:#fff;padding:40px;border:1px solid #dee2e6;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,0.04);text-align:center}
.error-page .error-code{font-size:80px;font-weight:700;color:#1d3557;line-height:1;margin-bottom:12px}
.error-page .error-title{font-size:22px;font-weight:600;color:#495057;margin-bottom:16px}
.error-page .error-message{color:#6c757d;font-size:15px;margin-bottom:24px;max-width:500px;margin-left:auto;margin-right:auto}
.error-page .search-box{display:inline-flex;gap:4px;margin-bottom:20px}
.error-page .search-box input{padding:10px 14px;border:1px solid #ced4da;border-radius:4px;font-size:14px;width:280px}
.error-page .search-box button{padding:10px 18px;background:#457b9d;color:#fff;border:none;border-radius:4px;font-size:14px;cursor:pointer}
.error-page .search-box button:hover{background:#1d3557}
.error-page .home-link{display:inline-block;margin-top:8px;color:#457b9d;font-size:14px}
.module{background:#fff;padding:20px;margin-bottom:20px;border:1px solid #dee2e6;border-radius:4px}
.module h3{font-size:15px;font-weight:600;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #eee;color:#1d3557}
.module ul{list-style:none;padding:0}
.module li{padding:5px 0;border-bottom:1px solid #f5f5f5;font-size:14px}
.module li:last-child{border-bottom:none}
.module li a{color:#457b9d}
.site-footer{background:#1d3557;color:#a8dadc;text-align:center;padding:20px;font-size:13px;margin-top:40px}
.site-footer a{color:#fff}
@media(max-width:768px){.main-wrapper{flex-direction:column}.sidebar{width:100%}.error-page .search-box{flex-direction:column}.error-page .search-box input{width:100%}}
</style>
</head>
<body class="site com_content">

<div class="header-wrapper">
<div class="container">
<header class="site-header">
<h1><a href="<?= $siteUrl ?>/"><?= $siteName ?></a></h1>
<div class="header-search">
<form action="<?= $siteUrl ?>/index.php" method="get">
<input type="hidden" name="option" value="com_finder">
<input type="hidden" name="view" value="search">
<input type="search" name="q" placeholder="Search...">
<button type="submit">Go</button>
</form>
</div>
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

<div class="error-page">
    <div class="error-code">404</div>
    <div class="error-title">Article not found</div>
    <div class="error-message">The article you were looking for does not exist. It may have been moved or deleted. Try searching our site or return to the home page.</div>

    <div class="search-box">
        <form action="<?= $siteUrl ?>/index.php" method="get" style="display:inline-flex;gap:4px;">
            <input type="hidden" name="option" value="com_finder">
            <input type="hidden" name="view" value="search">
            <input type="search" name="q" placeholder="Search articles...">
            <button type="submit">Search</button>
        </form>
    </div>

    <div><a href="<?= $siteUrl ?>/" class="home-link">&larr; Return to home page</a></div>
</div>

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
<h3>Popular Articles</h3>
<ul>
<li><a href="<?= $siteUrl ?>/welcome">Welcome to <?= $siteName ?></a></li>
<li><a href="<?= $siteUrl ?>/our-services">Our Services</a></li>
<li><a href="<?= $siteUrl ?>/latest-news">Latest News</a></li>
</ul>
</div>
</aside>
</div>

<footer class="site-footer">
<p>&copy; <?= $year ?> <?= $siteName ?>. All Rights Reserved.</p>
<p><a href="https://www.joomla.org">Joomla!</a> is Free Software released under the <a href="https://www.gnu.org/licenses/gpl-2.0.html">GNU General Public License</a>.</p>
</footer>

</body>
</html>
