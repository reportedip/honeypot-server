<?php
/**
 * WordPress admin dashboard template.
 *
 * Variables: $site_name, $site_url, $wp_version, $request_path
 */

$siteUrl = htmlspecialchars($site_url ?? '', ENT_QUOTES, 'UTF-8');
$siteName = htmlspecialchars($site_name ?? 'My WordPress Site', ENT_QUOTES, 'UTF-8');
$version = htmlspecialchars($wp_version ?? '6.4.2', ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Dashboard &lsaquo; <?php echo $siteName; ?> &#8212; WordPress</title>
<style type="text/css">
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif;font-size:13px;line-height:1.4;color:#3c434a;background:#f0f0f1}
a{color:#2271b1;text-decoration:none}
a:hover{color:#135e96}
#wpadminbar{position:fixed;top:0;left:0;right:0;height:32px;background:#1d2327;z-index:9999;display:flex;align-items:center;padding:0 10px}
#wpadminbar .ab-item{color:#c3c4c7;font-size:13px;padding:0 8px;line-height:32px;display:inline-block}
#wpadminbar .ab-item:hover{color:#72aee6}
#wpadminbar .wp-logo{margin-right:10px}
#wpadminbar .wp-logo .ab-item{padding:0 7px}
#wpadminbar .site-name{font-weight:600}
#adminmenuwrap{position:fixed;top:32px;left:0;bottom:0;width:160px;background:#1d2327;overflow-y:auto}
#adminmenu{list-style:none;margin:0;padding:0}
#adminmenu li a{display:block;padding:8px 12px;color:#c3c4c7;font-size:14px;border-left:4px solid transparent;text-decoration:none}
#adminmenu li a:hover{background:#2c3338;color:#72aee6}
#adminmenu li.current a{background:#2271b1;color:#fff;border-left-color:#72aee6}
#adminmenu .menu-sep{border-bottom:1px solid #3c434a;margin:0}
#adminmenu .dashicons{margin-right:6px;font-size:16px;vertical-align:middle}
#wpcontent{margin-left:160px;padding-top:32px}
.wrap{margin:10px 20px 0 2px;padding:0 20px}
.wrap h1{font-size:23px;font-weight:400;margin:0;padding:9px 0 4px;line-height:1.3}
#welcome-panel{background:#fff;border:1px solid #c3c4c7;padding:23px 10px 0;margin:16px 0;position:relative}
#welcome-panel h2{margin:0;font-size:16px;font-weight:400;line-height:1.4;padding-left:12px}
#welcome-panel p{padding:0 12px;margin:8px 0}
#welcome-panel .welcome-panel-column-container{display:flex;gap:20px;padding:12px}
.welcome-panel-column{flex:1}
.welcome-panel-column h3{font-size:14px}
.welcome-panel-column ul{list-style:none;padding:0}
.welcome-panel-column li{padding:4px 0}
#dashboard-widgets-wrap{display:flex;gap:20px;margin-top:20px;flex-wrap:wrap}
.postbox-container{flex:1;min-width:300px}
.postbox{background:#fff;border:1px solid #c3c4c7;margin-bottom:20px}
.postbox .hndle{border-bottom:1px solid #c3c4c7;padding:8px 12px;font-size:14px;font-weight:600}
.postbox .inside{padding:12px;font-size:13px;line-height:1.7}
.postbox .inside ul{list-style:disc;padding-left:20px;margin:0}
.postbox .inside li{margin-bottom:4px}
.at-a-glance .icon{font-size:48px;color:#c3c4c7;float:right;margin:0 12px}
.at-a-glance ul{list-style:none;padding:0}
.at-a-glance li{display:inline-block;margin-right:12px;padding:4px 0}
.at-a-glance a{font-size:14px}
#footer{position:fixed;bottom:0;left:160px;right:0;padding:8px 20px;background:#f0f0f1;font-size:12px;color:#50575e;border-top:1px solid #c3c4c7}
#footer a{color:#2271b1}
@media(max-width:782px){#adminmenuwrap{width:36px}#wpcontent{margin-left:36px}#adminmenu li a{font-size:0;padding:12px}#footer{left:36px}}
</style>
</head>
<body class="wp-admin wp-core-ui">

<div id="wpadminbar">
<div class="wp-logo"><span class="ab-item">W</span></div>
<a class="ab-item site-name" href="<?php echo $siteUrl; ?>/"><?php echo $siteName; ?></a>
<a class="ab-item" href="<?php echo $siteUrl; ?>/wp-admin/customize.php">Customize</a>
<a class="ab-item" href="<?php echo $siteUrl; ?>/wp-admin/post-new.php">+ New</a>
<span style="flex:1"></span>
<a class="ab-item" href="<?php echo $siteUrl; ?>/wp-admin/profile.php">Howdy, admin</a>
</div>

<div id="adminmenuwrap">
<ul id="adminmenu">
<li class="current"><a href="<?php echo $siteUrl; ?>/wp-admin/">Dashboard</a></li>
<li><a href="<?php echo $siteUrl; ?>/wp-admin/update-core.php">Updates <span style="background:#d63638;color:#fff;font-size:11px;padding:0 6px;border-radius:10px;margin-left:4px">3</span></a></li>
<li class="menu-sep"></li>
<li><a href="<?php echo $siteUrl; ?>/wp-admin/edit.php">Posts</a></li>
<li><a href="<?php echo $siteUrl; ?>/wp-admin/upload.php">Media</a></li>
<li><a href="<?php echo $siteUrl; ?>/wp-admin/edit.php?post_type=page">Pages</a></li>
<li><a href="<?php echo $siteUrl; ?>/wp-admin/edit-comments.php">Comments</a></li>
<li class="menu-sep"></li>
<li><a href="<?php echo $siteUrl; ?>/wp-admin/themes.php">Appearance</a></li>
<li><a href="<?php echo $siteUrl; ?>/wp-admin/plugins.php">Plugins</a></li>
<li><a href="<?php echo $siteUrl; ?>/wp-admin/users.php">Users</a></li>
<li><a href="<?php echo $siteUrl; ?>/wp-admin/tools.php">Tools</a></li>
<li><a href="<?php echo $siteUrl; ?>/wp-admin/options-general.php">Settings</a></li>
<li class="menu-sep"></li>
<li><a href="<?php echo $siteUrl; ?>/wp-admin/edit.php?post_type=product">WooCommerce</a></li>
</ul>
</div>

<div id="wpcontent">
<div class="wrap">
<h1>Dashboard</h1>

<div id="welcome-panel">
<h2>Welcome to WordPress!</h2>
<p class="about-description">We have gathered some links to get you started:</p>
<div class="welcome-panel-column-container">
<div class="welcome-panel-column">
<h3>Get Started</h3>
<a href="<?php echo $siteUrl; ?>/wp-admin/customize.php">Customize Your Site</a>
</div>
<div class="welcome-panel-column">
<h3>Next Steps</h3>
<ul>
<li><a href="<?php echo $siteUrl; ?>/wp-admin/post-new.php?post_type=page">Edit your front page</a></li>
<li><a href="<?php echo $siteUrl; ?>/wp-admin/post-new.php">Write your first blog post</a></li>
<li><a href="<?php echo $siteUrl; ?>/wp-admin/widgets.php">Manage widgets</a></li>
</ul>
</div>
<div class="welcome-panel-column">
<h3>More Actions</h3>
<ul>
<li><a href="<?php echo $siteUrl; ?>/wp-admin/nav-menus.php">Manage menus</a></li>
<li><a href="<?php echo $siteUrl; ?>/wp-admin/options-discussion.php">Turn comments on or off</a></li>
<li><a href="https://wordpress.org/documentation/">Learn more about getting started</a></li>
</ul>
</div>
</div>
</div>

<div id="dashboard-widgets-wrap">
<div class="postbox-container">
<div class="postbox at-a-glance">
<h2 class="hndle">At a Glance</h2>
<div class="inside">
<ul>
<li><a href="<?php echo $siteUrl; ?>/wp-admin/edit.php">3 Posts</a></li>
<li><a href="<?php echo $siteUrl; ?>/wp-admin/edit.php?post_type=page">2 Pages</a></li>
<li><a href="<?php echo $siteUrl; ?>/wp-admin/edit-comments.php">1 Comment</a></li>
</ul>
<p>WordPress <?php echo $version; ?> running Twenty Twenty-Four theme.</p>
</div>
</div>

<div class="postbox">
<h2 class="hndle">Activity</h2>
<div class="inside">
<h3>Recently Published</h3>
<ul>
<li><a href="<?php echo $siteUrl; ?>/wp-admin/post.php?post=3&action=edit">Latest Company News and Updates</a> &mdash; March 10, 2024</li>
<li><a href="<?php echo $siteUrl; ?>/wp-admin/post.php?post=2&action=edit">Getting Started with Our Services</a> &mdash; February 3, 2024</li>
<li><a href="<?php echo $siteUrl; ?>/wp-admin/post.php?post=1&action=edit">Hello world!</a> &mdash; January 15, 2024</li>
</ul>
<h3 style="margin-top:12px">Recent Comments</h3>
<ul>
<li>A WordPress Commenter on <a href="<?php echo $siteUrl; ?>/hello-world/#comment-1">Hello world!</a></li>
</ul>
</div>
</div>
</div>

<div class="postbox-container">
<div class="postbox">
<h2 class="hndle">Quick Draft</h2>
<div class="inside">
<form action="<?php echo $siteUrl; ?>/wp-admin/post.php?action=post-quickdraft-save" method="post">
<p><label>Title<br><input type="text" name="post_title" style="width:100%;padding:4px 8px;border:1px solid #8c8f94;border-radius:4px"></label></p>
<p><label>Content<br><textarea name="content" rows="3" style="width:100%;padding:4px 8px;border:1px solid #8c8f94;border-radius:4px;resize:vertical"></textarea></label></p>
<p><input type="submit" value="Save Draft" style="padding:4px 12px;background:#2271b1;color:#fff;border:1px solid #2271b1;border-radius:3px;cursor:pointer"></p>
</form>
</div>
</div>

<div class="postbox">
<h2 class="hndle">WordPress Events and News</h2>
<div class="inside">
<ul>
<li><strong>WordPress 6.5 Planning</strong> &mdash; Upcoming features and improvements.</li>
<li><strong>WordCamp Asia 2024</strong> &mdash; Join us in Taipei on March 7-9, 2024.</li>
<li><strong>Plugin Security Update</strong> &mdash; Keep your plugins up to date.</li>
</ul>
</div>
</div>

<div class="postbox">
<h2 class="hndle">Site Health Status</h2>
<div class="inside">
<p>Your site has <strong>2 critical issues</strong> that should be addressed as soon as possible.</p>
<ul>
<li>An update is available for your PHP version (8.2.14)</li>
<li>3 plugin updates available</li>
</ul>
</div>
</div>
</div>
</div>

</div>
</div>

<div id="footer">
Thank you for creating with <a href="https://wordpress.org/">WordPress</a>. &mdash; Version <?php echo $version; ?>
</div>

</body>
</html>
