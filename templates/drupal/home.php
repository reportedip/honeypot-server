<?php
/**
 * Drupal homepage template.
 *
 * Variables: $site_name, $site_url, $drupal_version, $theme, $language,
 *            Optional: $is_search_page, $search_term, $search_results,
 *                      $is_contact_page, $contact_success, $contact_message,
 *                      $show_contact_form, $comment_notice, $message,
 *                      $is_user_profile, $user_name, $user_id
 */

$siteUrl = htmlspecialchars($site_url ?? '', ENT_QUOTES, 'UTF-8');
$siteName = htmlspecialchars($site_name ?? 'My Drupal Site', ENT_QUOTES, 'UTF-8');
$version = htmlspecialchars($drupal_version ?? '10.2.2', ENT_QUOTES, 'UTF-8');
$year = date('Y');
?>
<!DOCTYPE html>
<html lang="<?php echo htmlspecialchars($language ?? 'en', ENT_QUOTES, 'UTF-8'); ?>" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="Generator" content="Drupal 10 (https://www.drupal.org)">
<title><?php
if (!empty($is_search_page)) {
    echo 'Search for ' . ($search_term ?? '') . ' | ' . $siteName;
} elseif (!empty($is_contact_page)) {
    echo 'Contact | ' . $siteName;
} elseif (!empty($is_user_profile)) {
    echo htmlspecialchars($user_name ?? 'admin', ENT_QUOTES, 'UTF-8') . ' | ' . $siteName;
} else {
    echo 'Welcome to ' . $siteName . ' | ' . $siteName;
}
?></title>
<style type="text/css">
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:"Source Sans Pro",sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial;font-size:16px;line-height:1.6;color:#232629;background:#e7e4df}
a{color:#003cc5;text-decoration:underline}
a:hover{color:#002e9a}
.dialog-off-canvas-main-canvas{display:flex;flex-direction:column;min-height:100vh}
header.site-header{background:#1b1b1b;color:#fff;padding:0}
.site-branding{max-width:1200px;margin:0 auto;padding:16px 20px;display:flex;align-items:center;justify-content:space-between}
.site-branding h1{font-size:24px;font-weight:700;margin:0}
.site-branding h1 a{color:#fff;text-decoration:none}
.site-branding h1 a:hover{color:#55b3ea}
nav.main-nav{background:#2d2d2d}
nav.main-nav ul{list-style:none;max-width:1200px;margin:0 auto;padding:0 20px;display:flex}
nav.main-nav li{margin:0}
nav.main-nav a{display:block;padding:12px 18px;color:#d4d4d8;text-decoration:none;font-size:15px}
nav.main-nav a:hover{background:#3d3d3d;color:#fff}
.region-highlighted{background:#fff3cd;border-bottom:1px solid #e6c46c;padding:12px 20px;max-width:1200px;margin:0 auto}
.main-content-wrapper{max-width:1200px;margin:30px auto;padding:0 20px;display:flex;gap:30px;flex:1}
main.main-content{flex:1;min-width:0}
aside.sidebar{width:280px;flex-shrink:0}
.node{background:#fff;padding:30px;margin-bottom:25px;border:1px solid #d3d4d9;border-radius:4px}
.node .node-title{font-size:22px;margin-bottom:8px;font-weight:700}
.node .node-title a{color:#003cc5;text-decoration:none}
.node .node-title a:hover{text-decoration:underline}
.node .node-meta{color:#57575d;font-size:13px;margin-bottom:15px}
.node .node-content p{margin-bottom:12px}
.node .read-more{display:inline-block;padding:8px 16px;background:#003cc5;color:#fff;text-decoration:none;font-size:13px;border-radius:4px;margin-top:8px}
.node .read-more:hover{background:#002e9a;color:#fff}
.block{background:#fff;padding:20px;margin-bottom:20px;border:1px solid #d3d4d9;border-radius:4px}
.block h2{font-size:16px;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #eee}
.block ul{list-style:none;padding:0}
.block li{padding:5px 0;border-bottom:1px solid #f5f5f5;font-size:14px}
.block li:last-child{border-bottom:none}
footer.site-footer{background:#1b1b1b;color:#929296;text-align:center;padding:20px;font-size:13px;margin-top:auto}
footer.site-footer a{color:#55b3ea}
.status-message{background:#d4edda;border:1px solid #c3e6cb;padding:12px 20px;margin-bottom:20px;color:#155724;border-radius:4px}
.search-form{margin-bottom:20px}
.search-form input[type="search"]{padding:8px 12px;width:300px;border:1px solid #8e929c;font-size:14px;border-radius:4px}
.search-form button{padding:8px 16px;background:#003cc5;color:#fff;border:none;cursor:pointer;font-size:14px;border-radius:4px}
.user-profile{background:#fff;padding:30px;border:1px solid #d3d4d9;border-radius:4px;margin-bottom:25px}
.user-profile h2{font-size:22px;margin-bottom:10px}
.user-profile .field{margin-bottom:10px}
.user-profile .field-label{font-weight:700;color:#57575d;font-size:13px;text-transform:uppercase}
@media(max-width:768px){.main-content-wrapper{flex-direction:column}aside.sidebar{width:100%}}
</style>
</head>
<body>
<div class="dialog-off-canvas-main-canvas">

<header class="site-header">
<div class="site-branding">
<h1><a href="<?php echo $siteUrl; ?>/"><?php echo $siteName; ?></a></h1>
<div style="color:#929296;font-size:13px">Powered by Drupal</div>
</div>
</header>

<nav class="main-nav">
<ul>
<li><a href="<?php echo $siteUrl; ?>/">Home</a></li>
<li><a href="<?php echo $siteUrl; ?>/about">About</a></li>
<li><a href="<?php echo $siteUrl; ?>/articles">Articles</a></li>
<li><a href="<?php echo $siteUrl; ?>/contact">Contact</a></li>
</ul>
</nav>

<div class="main-content-wrapper">
<main class="main-content">

<?php if (!empty($comment_notice) && !empty($message)): ?>
<div class="status-message"><?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?></div>
<?php endif; ?>

<?php if (!empty($contact_success)): ?>
<div class="status-message"><?php echo htmlspecialchars($contact_message ?? '', ENT_QUOTES, 'UTF-8'); ?></div>
<?php endif; ?>

<?php if (!empty($is_search_page)): ?>
<h1 style="font-size:22px;margin-bottom:20px">Search results</h1>
<div class="search-form">
<form method="get" action="<?php echo $siteUrl; ?>/search">
<input type="search" name="keys" value="<?php echo $search_term ?? ''; ?>" placeholder="Search">
<button type="submit">Search</button>
</form>
</div>
<?php if (!empty($search_results)): ?>
<?php foreach ($search_results as $result): ?>
<article class="node">
<h2 class="node-title"><a href="<?php echo htmlspecialchars($result['url'], ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars($result['title'], ENT_QUOTES, 'UTF-8'); ?></a></h2>
<div class="node-content"><p><?php echo htmlspecialchars($result['excerpt'], ENT_QUOTES, 'UTF-8'); ?></p></div>
</article>
<?php endforeach; ?>
<?php else: ?>
<div class="node"><p>Your search yielded no results.</p></div>
<?php endif; ?>

<?php elseif (!empty($is_contact_page) && !empty($show_contact_form)): ?>
<article class="node">
<h2 class="node-title">Website feedback</h2>
<div class="node-content">
<form method="post" action="<?php echo $siteUrl; ?>/contact">
<div style="margin-bottom:12px"><label style="font-weight:700;display:block;margin-bottom:4px">Your name</label><input type="text" name="name" style="width:100%;padding:8px;border:1px solid #8e929c;border-radius:4px"></div>
<div style="margin-bottom:12px"><label style="font-weight:700;display:block;margin-bottom:4px">Your email address</label><input type="email" name="mail" style="width:100%;padding:8px;border:1px solid #8e929c;border-radius:4px"></div>
<div style="margin-bottom:12px"><label style="font-weight:700;display:block;margin-bottom:4px">Subject</label><input type="text" name="subject" style="width:100%;padding:8px;border:1px solid #8e929c;border-radius:4px"></div>
<div style="margin-bottom:12px"><label style="font-weight:700;display:block;margin-bottom:4px">Message</label><textarea name="message" rows="8" style="width:100%;padding:8px;border:1px solid #8e929c;border-radius:4px"></textarea></div>
<button type="submit" style="padding:10px 20px;background:#003cc5;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:14px">Send message</button>
</form>
</div>
</article>

<?php elseif (!empty($is_user_profile)): ?>
<div class="user-profile">
<h2><?php echo htmlspecialchars($user_name ?? 'admin', ENT_QUOTES, 'UTF-8'); ?></h2>
<div class="field"><div class="field-label">Member for</div><div>3 years 2 months</div></div>
<div class="field"><div class="field-label">Last access</div><div><?php echo date('D, m/d/Y - H:i'); ?></div></div>
</div>

<?php else: ?>

<?php if (!empty($generated_posts)): ?>
<?php foreach ($generated_posts as $gp): ?>
<article class="node">
<h2 class="node-title"><a href="<?php echo htmlspecialchars($gp['url'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars($gp['title'] ?? '', ENT_QUOTES, 'UTF-8'); ?></a></h2>
<div class="node-meta">Submitted by <a href="<?php echo $siteUrl; ?>/user/1"><?php echo htmlspecialchars($gp['author'] ?? 'admin', ENT_QUOTES, 'UTF-8'); ?></a> on <?php echo date('D, m/d/Y - H:i', strtotime($gp['published_date'] ?? 'now')); ?></div>
<div class="node-content">
<p><?php echo htmlspecialchars($gp['excerpt'] ?? '', ENT_QUOTES, 'UTF-8'); ?></p>
</div>
<a href="<?php echo htmlspecialchars($gp['url'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" class="read-more">Read more</a>
</article>
<?php endforeach; ?>
<?php else: ?>

<article class="node">
<h2 class="node-title"><a href="<?php echo $siteUrl; ?>/node/3">Welcome to <?php echo $siteName; ?></a></h2>
<div class="node-meta">Submitted by <a href="<?php echo $siteUrl; ?>/user/1">admin</a> on <?php echo date('D, m/d/Y - H:i'); ?></div>
<div class="node-content">
<p>Welcome to our website built with Drupal, the powerful open-source content management platform. We are committed to providing high-quality content and services to our community.</p>
</div>
<a href="<?php echo $siteUrl; ?>/node/3" class="read-more">Read more</a>
</article>

<article class="node">
<h2 class="node-title"><a href="<?php echo $siteUrl; ?>/node/2">Getting Started Guide</a></h2>
<div class="node-meta">Submitted by <a href="<?php echo $siteUrl; ?>/user/1">admin</a> on January 20, 2024</div>
<div class="node-content">
<p>This guide will help you understand the basics of navigating our site. Whether you are looking for information about our services or want to contribute content, this is the right place to start.</p>
</div>
<a href="<?php echo $siteUrl; ?>/node/2" class="read-more">Read more</a>
</article>

<article class="node">
<h2 class="node-title"><a href="<?php echo $siteUrl; ?>/node/1">Our First Article</a></h2>
<div class="node-meta">Submitted by <a href="<?php echo $siteUrl; ?>/user/1">admin</a> on January 15, 2024</div>
<div class="node-content">
<p>We are excited to share our first article on this new platform. Stay tuned for more updates and articles about our projects and community initiatives.</p>
</div>
<a href="<?php echo $siteUrl; ?>/node/1" class="read-more">Read more</a>
</article>
<?php endif; ?>

<?php endif; ?>

</main>

<aside class="sidebar">
<div class="block">
<h2>Search</h2>
<form method="get" action="<?php echo $siteUrl; ?>/search">
<input type="search" name="keys" placeholder="Search" style="width:100%;padding:8px;border:1px solid #8e929c;font-size:14px;border-radius:4px">
</form>
</div>

<div class="block">
<h2>Navigation</h2>
<ul>
<li><a href="<?php echo $siteUrl; ?>/node/add">Add content</a></li>
<li><a href="<?php echo $siteUrl; ?>/admin/content">Content administration</a></li>
</ul>
</div>

<div class="block">
<h2>User login</h2>
<form method="post" action="<?php echo $siteUrl; ?>/user/login">
<div style="margin-bottom:8px"><label style="font-size:13px;display:block">Username</label><input type="text" name="name" style="width:100%;padding:6px;border:1px solid #8e929c;border-radius:3px;font-size:13px"></div>
<div style="margin-bottom:8px"><label style="font-size:13px;display:block">Password</label><input type="password" name="pass" style="width:100%;padding:6px;border:1px solid #8e929c;border-radius:3px;font-size:13px"></div>
<button type="submit" style="padding:6px 14px;background:#003cc5;color:#fff;border:none;border-radius:3px;cursor:pointer;font-size:13px">Log in</button>
<div style="margin-top:8px;font-size:12px">
<a href="<?php echo $siteUrl; ?>/user/register">Create new account</a> |
<a href="<?php echo $siteUrl; ?>/user/password">Reset your password</a>
</div>
</form>
</div>

<div class="block">
<h2>Recent content</h2>
<ul>
<?php if (!empty($generated_posts)): ?>
    <?php foreach (array_slice($generated_posts, 0, 5) as $rp): ?>
    <li><a href="<?php echo htmlspecialchars($rp['url'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars($rp['title'] ?? '', ENT_QUOTES, 'UTF-8'); ?></a></li>
    <?php endforeach; ?>
<?php else: ?>
    <li><a href="<?php echo $siteUrl; ?>/node/3">Welcome to <?php echo $siteName; ?></a></li>
    <li><a href="<?php echo $siteUrl; ?>/node/2">Getting Started Guide</a></li>
    <li><a href="<?php echo $siteUrl; ?>/node/1">Our First Article</a></li>
<?php endif; ?>
</ul>
</div>
</aside>
</div>

<footer class="site-footer">
<p>&copy; <?php echo $year; ?> <?php echo $siteName; ?>. All rights reserved.</p>
<p>Powered by <a href="https://www.drupal.org">Drupal</a></p>
</footer>

</div>
</body>
</html>
