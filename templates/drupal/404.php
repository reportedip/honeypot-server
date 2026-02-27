<?php
/**
 * Drupal 404 page template.
 *
 * Variables: $site_name, $site_url, $drupal_version, $request_path, $language
 */

$siteUrl = htmlspecialchars($site_url ?? '', ENT_QUOTES, 'UTF-8');
$siteName = htmlspecialchars($site_name ?? 'My Drupal Site', ENT_QUOTES, 'UTF-8');
$year = date('Y');
?>
<!DOCTYPE html>
<html lang="<?php echo htmlspecialchars($language ?? 'en', ENT_QUOTES, 'UTF-8'); ?>" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="Generator" content="Drupal 10 (https://www.drupal.org)">
<title>Page not found | <?php echo $siteName; ?></title>
<style type="text/css">
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:"Source Sans Pro",sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial;font-size:16px;line-height:1.6;color:#232629;background:#e7e4df}
a{color:#003cc5;text-decoration:underline}
a:hover{color:#002e9a}
header.site-header{background:#1b1b1b;color:#fff;padding:0}
.site-branding{max-width:1200px;margin:0 auto;padding:16px 20px}
.site-branding h1{font-size:24px;margin:0}
.site-branding h1 a{color:#fff;text-decoration:none}
nav.main-nav{background:#2d2d2d}
nav.main-nav ul{list-style:none;max-width:1200px;margin:0 auto;padding:0 20px;display:flex}
nav.main-nav a{display:block;padding:12px 18px;color:#d4d4d8;text-decoration:none;font-size:15px}
nav.main-nav a:hover{background:#3d3d3d;color:#fff}
.page-content{max-width:1200px;margin:40px auto;padding:0 20px}
.error-page{background:#fff;padding:40px;border:1px solid #d3d4d9;border-radius:4px}
.error-page h1{font-size:28px;margin-bottom:15px;color:#232629}
.error-page p{margin-bottom:12px;color:#57575d}
.search-form{margin:20px 0}
.search-form input[type="search"]{padding:8px 12px;width:300px;border:1px solid #8e929c;font-size:14px;border-radius:4px}
.search-form button{padding:8px 16px;background:#003cc5;color:#fff;border:none;cursor:pointer;font-size:14px;border-radius:4px}
footer.site-footer{background:#1b1b1b;color:#929296;text-align:center;padding:20px;font-size:13px;margin-top:60px}
footer.site-footer a{color:#55b3ea}
</style>
</head>
<body>

<header class="site-header">
<div class="site-branding">
<h1><a href="<?php echo $siteUrl; ?>/"><?php echo $siteName; ?></a></h1>
</div>
</header>

<nav class="main-nav">
<ul>
<li><a href="<?php echo $siteUrl; ?>/">Home</a></li>
<li><a href="<?php echo $siteUrl; ?>/about">About</a></li>
<li><a href="<?php echo $siteUrl; ?>/contact">Contact</a></li>
</ul>
</nav>

<div class="page-content">
<div class="error-page">
<h1>Page not found</h1>
<p>The requested page could not be found.</p>
<div class="search-form">
<form method="get" action="<?php echo $siteUrl; ?>/search">
<input type="search" name="keys" placeholder="Search">
<button type="submit">Search</button>
</form>
</div>
</div>
</div>

<footer class="site-footer">
<p>&copy; <?php echo $year; ?> <?php echo $siteName; ?>. Powered by <a href="https://www.drupal.org">Drupal</a></p>
</footer>

</body>
</html>
