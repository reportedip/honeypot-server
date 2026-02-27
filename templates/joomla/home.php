<?php
/**
 * Joomla homepage template.
 *
 * Variables: $site_name, $site_url, $joomla_version, $template, $language,
 *            Optional: $is_search_page, $search_term, $search_results,
 *                      $is_contact_page, $contact_success, $contact_message,
 *                      $show_contact_form, $comment_notice, $message
 */

$siteUrl = htmlspecialchars($site_url ?? '', ENT_QUOTES, 'UTF-8');
$siteName = htmlspecialchars($site_name ?? 'My Joomla Site', ENT_QUOTES, 'UTF-8');
$version = htmlspecialchars($joomla_version ?? '4.4.2', ENT_QUOTES, 'UTF-8');
$year = date('Y');
?>
<!DOCTYPE html>
<html lang="<?php echo htmlspecialchars($language ?? 'en-GB', ENT_QUOTES, 'UTF-8'); ?>" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="Joomla! - Open Source Content Management - Version <?php echo $version; ?>">
<title><?php
if (!empty($is_search_page)) {
    echo 'Search: ' . ($search_term ?? '') . ' - ' . $siteName;
} elseif (!empty($is_contact_page)) {
    echo 'Contact - ' . $siteName;
} else {
    echo $siteName;
}
?></title>
<style type="text/css">
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:"Roboto",-apple-system,BlinkMacSystemFont,"Segoe UI","Helvetica Neue",Arial,sans-serif;font-size:16px;line-height:1.6;color:#212529;background:#f4f6f7}
a{color:#457b9d;text-decoration:none}
a:hover{color:#1d3557;text-decoration:underline}
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
nav.top-nav li{margin:0}
nav.top-nav a{display:block;padding:12px 18px;color:#a8dadc;font-size:14px;text-decoration:none}
nav.top-nav a:hover{background:#1d3557;color:#fff}
.main-wrapper{max-width:1200px;margin:30px auto;padding:0 20px;display:flex;gap:30px}
.main-content{flex:1;min-width:0}
.sidebar{width:280px;flex-shrink:0}
.item-page{background:#fff;padding:30px;margin-bottom:25px;border:1px solid #dee2e6;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,0.04)}
.item-page .page-header h2{font-size:22px;margin-bottom:8px;font-weight:600}
.item-page .page-header h2 a{color:#1d3557}
.item-page .article-info{color:#6c757d;font-size:13px;margin-bottom:15px}
.item-page .article-info span{margin-right:12px}
.item-page .article-content p{margin-bottom:12px}
.item-page .readmore a{display:inline-block;padding:8px 16px;background:#457b9d;color:#fff;border-radius:3px;font-size:13px;text-decoration:none}
.item-page .readmore a:hover{background:#1d3557;color:#fff}
.module{background:#fff;padding:20px;margin-bottom:20px;border:1px solid #dee2e6;border-radius:4px}
.module h3{font-size:15px;font-weight:600;margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid #eee;color:#1d3557}
.module ul{list-style:none;padding:0}
.module li{padding:5px 0;border-bottom:1px solid #f5f5f5;font-size:14px}
.module li:last-child{border-bottom:none}
.module li a{color:#457b9d}
.module li a:hover{color:#1d3557}
.site-footer{background:#1d3557;color:#a8dadc;text-align:center;padding:20px;font-size:13px;margin-top:40px}
.site-footer a{color:#fff}
.alert-success{background:#d1e7dd;border:1px solid #badbcc;padding:12px 20px;margin-bottom:20px;color:#0f5132;border-radius:4px}
.search-results h2{margin-bottom:20px;font-size:22px}
.search-form{margin-bottom:20px}
.search-form input[type="search"]{padding:8px 12px;width:300px;border:1px solid #ced4da;font-size:14px;border-radius:3px}
.search-form button{padding:8px 16px;background:#457b9d;color:#fff;border:none;cursor:pointer;font-size:14px;border-radius:3px}
@media(max-width:768px){.main-wrapper{flex-direction:column}.sidebar{width:100%}}
</style>
</head>
<body class="site com_content">

<div class="header-wrapper">
<div class="container">
<header class="site-header">
<h1><a href="<?php echo $siteUrl; ?>/"><?php echo $siteName; ?></a></h1>
<div class="header-search">
<form action="<?php echo $siteUrl; ?>/index.php" method="get">
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
<li><a href="<?php echo $siteUrl; ?>/">Home</a></li>
<li><a href="<?php echo $siteUrl; ?>/about">About Us</a></li>
<li><a href="<?php echo $siteUrl; ?>/services">Services</a></li>
<li><a href="<?php echo $siteUrl; ?>/blog">Blog</a></li>
<li><a href="<?php echo $siteUrl; ?>/contact">Contact</a></li>
</ul>
</nav>

<div class="main-wrapper">
<main class="main-content">

<?php if (!empty($comment_notice) && !empty($message)): ?>
<div class="alert-success"><?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?></div>
<?php endif; ?>

<?php if (!empty($contact_success)): ?>
<div class="alert-success"><?php echo htmlspecialchars($contact_message ?? '', ENT_QUOTES, 'UTF-8'); ?></div>
<?php endif; ?>

<?php if (!empty($is_search_page)): ?>
<h2 class="search-results">Search results for: <?php echo $search_term ?? ''; ?></h2>
<div class="search-form">
<form action="<?php echo $siteUrl; ?>/index.php" method="get">
<input type="hidden" name="option" value="com_finder">
<input type="hidden" name="view" value="search">
<input type="search" name="q" value="<?php echo $search_term ?? ''; ?>">
<button type="submit">Search</button>
</form>
</div>
<?php if (!empty($search_results)): ?>
<?php foreach ($search_results as $result): ?>
<div class="item-page">
<div class="page-header"><h2><a href="<?php echo htmlspecialchars($result['url'], ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars($result['title'], ENT_QUOTES, 'UTF-8'); ?></a></h2></div>
<div class="article-content"><p><?php echo htmlspecialchars($result['excerpt'], ENT_QUOTES, 'UTF-8'); ?></p></div>
</div>
<?php endforeach; ?>
<?php else: ?>
<div class="item-page"><p>No results were found for your search query. Please try different keywords.</p></div>
<?php endif; ?>

<?php elseif (!empty($is_contact_page) && !empty($show_contact_form)): ?>
<div class="item-page">
<div class="page-header"><h2>Contact Us</h2></div>
<div class="article-content">
<form method="post" action="<?php echo $siteUrl; ?>/contact">
<div style="margin-bottom:12px"><label style="display:block;font-weight:600;margin-bottom:4px">Name <span style="color:#dc3545">*</span></label><input type="text" name="jform[contact_name]" style="width:100%;padding:8px;border:1px solid #ced4da;border-radius:3px"></div>
<div style="margin-bottom:12px"><label style="display:block;font-weight:600;margin-bottom:4px">Email <span style="color:#dc3545">*</span></label><input type="email" name="jform[contact_email]" style="width:100%;padding:8px;border:1px solid #ced4da;border-radius:3px"></div>
<div style="margin-bottom:12px"><label style="display:block;font-weight:600;margin-bottom:4px">Subject <span style="color:#dc3545">*</span></label><input type="text" name="jform[contact_subject]" style="width:100%;padding:8px;border:1px solid #ced4da;border-radius:3px"></div>
<div style="margin-bottom:12px"><label style="display:block;font-weight:600;margin-bottom:4px">Message <span style="color:#dc3545">*</span></label><textarea name="jform[contact_message]" rows="8" style="width:100%;padding:8px;border:1px solid #ced4da;border-radius:3px"></textarea></div>
<button type="submit" style="padding:10px 20px;background:#457b9d;color:#fff;border:none;border-radius:3px;cursor:pointer;font-size:14px">Send</button>
</form>
</div>
</div>

<?php else: ?>

<?php if (!empty($generated_posts)): ?>
<?php foreach ($generated_posts as $gp): ?>
<div class="item-page">
<div class="page-header"><h2><a href="<?php echo htmlspecialchars($gp['url'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars($gp['title'] ?? '', ENT_QUOTES, 'UTF-8'); ?></a></h2></div>
<div class="article-info">
<span>Written by <strong><?php echo htmlspecialchars($gp['author'] ?? 'Super User', ENT_QUOTES, 'UTF-8'); ?></strong></span>
<span>Category: <a href="<?php echo $siteUrl; ?>/category/<?php echo urlencode(strtolower(str_replace(' ', '-', $gp['category'] ?? 'uncategorised'))); ?>"><?php echo htmlspecialchars($gp['category'] ?? 'Uncategorised', ENT_QUOTES, 'UTF-8'); ?></a></span>
<span>Published: <?php echo date('d F Y', strtotime($gp['published_date'] ?? 'now')); ?></span>
</div>
<div class="article-content">
<p><?php echo htmlspecialchars($gp['excerpt'] ?? '', ENT_QUOTES, 'UTF-8'); ?></p>
</div>
<div class="readmore"><a href="<?php echo htmlspecialchars($gp['url'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">Read more: <?php echo htmlspecialchars($gp['title'] ?? '', ENT_QUOTES, 'UTF-8'); ?></a></div>
</div>
<?php endforeach; ?>
<?php else: ?>

<div class="item-page">
<div class="page-header"><h2><a href="<?php echo $siteUrl; ?>/welcome">Welcome to <?php echo $siteName; ?></a></h2></div>
<div class="article-info">
<span>Written by <strong>Super User</strong></span>
<span>Category: <a href="<?php echo $siteUrl; ?>/category/uncategorised">Uncategorised</a></span>
<span>Published: <?php echo date('d F Y'); ?></span>
</div>
<div class="article-content">
<p>Welcome to our Joomla-powered website. We are dedicated to providing the best services and keeping our visitors informed with the latest updates and news from our organization.</p>
<p>Feel free to explore our site and do not hesitate to contact us if you have any questions.</p>
</div>
<div class="readmore"><a href="<?php echo $siteUrl; ?>/welcome">Read more: Welcome to <?php echo $siteName; ?></a></div>
</div>

<div class="item-page">
<div class="page-header"><h2><a href="<?php echo $siteUrl; ?>/our-services">Our Services</a></h2></div>
<div class="article-info">
<span>Written by <strong>Super User</strong></span>
<span>Published: January 20, 2024</span>
</div>
<div class="article-content">
<p>We offer a wide range of professional services tailored to meet your needs. Our team of experts is ready to help you achieve your goals with proven solutions and methodologies.</p>
</div>
<div class="readmore"><a href="<?php echo $siteUrl; ?>/our-services">Read more: Our Services</a></div>
</div>

<div class="item-page">
<div class="page-header"><h2><a href="<?php echo $siteUrl; ?>/latest-news">Latest News and Announcements</a></h2></div>
<div class="article-info">
<span>Written by <strong>Super User</strong></span>
<span>Published: February 5, 2024</span>
</div>
<div class="article-content">
<p>Stay up to date with our latest news and announcements. We regularly share updates about our projects, events, and community initiatives. Subscribe to our newsletter for more information.</p>
</div>
<div class="readmore"><a href="<?php echo $siteUrl; ?>/latest-news">Read more: Latest News and Announcements</a></div>
</div>
<?php endif; ?>

<?php endif; ?>

</main>

<aside class="sidebar">
<div class="module">
<h3>Main Menu</h3>
<ul>
<li><a href="<?php echo $siteUrl; ?>/">Home</a></li>
<li><a href="<?php echo $siteUrl; ?>/about">About Us</a></li>
<li><a href="<?php echo $siteUrl; ?>/services">Services</a></li>
<li><a href="<?php echo $siteUrl; ?>/blog">Blog</a></li>
<li><a href="<?php echo $siteUrl; ?>/contact">Contact</a></li>
</ul>
</div>

<div class="module">
<h3>Login Form</h3>
<form method="post" action="<?php echo $siteUrl; ?>/index.php?option=com_users&task=user.login">
<div style="margin-bottom:8px"><label style="font-size:13px;display:block">Username</label><input type="text" name="username" style="width:100%;padding:6px;border:1px solid #ced4da;border-radius:3px;font-size:13px"></div>
<div style="margin-bottom:8px"><label style="font-size:13px;display:block">Password</label><input type="password" name="passwd" style="width:100%;padding:6px;border:1px solid #ced4da;border-radius:3px;font-size:13px"></div>
<div style="margin-bottom:8px;font-size:12px"><label><input type="checkbox" name="remember" value="yes"> Remember me</label></div>
<button type="submit" style="padding:6px 14px;background:#457b9d;color:#fff;border:none;border-radius:3px;cursor:pointer;font-size:13px;width:100%">Log in</button>
<div style="margin-top:8px;font-size:12px">
<a href="<?php echo $siteUrl; ?>/index.php?option=com_users&view=reset">Forgot your password?</a><br>
<a href="<?php echo $siteUrl; ?>/index.php?option=com_users&view=registration">Create an account</a>
</div>
</form>
</div>

<div class="module">
<h3>Latest Articles</h3>
<ul>
<?php if (!empty($generated_posts)): ?>
    <?php foreach (array_slice($generated_posts, 0, 5) as $rp): ?>
    <li><a href="<?php echo htmlspecialchars($rp['url'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"><?php echo htmlspecialchars($rp['title'] ?? '', ENT_QUOTES, 'UTF-8'); ?></a></li>
    <?php endforeach; ?>
<?php else: ?>
    <li><a href="<?php echo $siteUrl; ?>/latest-news">Latest News and Announcements</a></li>
    <li><a href="<?php echo $siteUrl; ?>/our-services">Our Services</a></li>
    <li><a href="<?php echo $siteUrl; ?>/welcome">Welcome to <?php echo $siteName; ?></a></li>
<?php endif; ?>
</ul>
</div>

<div class="module">
<h3>Syndicate</h3>
<ul>
<li><a href="<?php echo $siteUrl; ?>/index.php?format=feed&type=rss">RSS Feed</a></li>
<li><a href="<?php echo $siteUrl; ?>/index.php?format=feed&type=atom">Atom Feed</a></li>
</ul>
</div>
</aside>
</div>

<footer class="site-footer">
<p>&copy; <?php echo $year; ?> <?php echo $siteName; ?>. All Rights Reserved.</p>
<p><a href="https://www.joomla.org">Joomla!</a> is Free Software released under the <a href="https://www.gnu.org/licenses/gpl-2.0.html">GNU General Public License</a>.</p>
</footer>

</body>
</html>
