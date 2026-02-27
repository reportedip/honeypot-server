<?php
/**
 * Drupal admin interface template.
 *
 * Variables: $site_name, $site_url, $drupal_version, $request_path
 */

$siteUrl = htmlspecialchars($site_url ?? '', ENT_QUOTES, 'UTF-8');
$siteName = htmlspecialchars($site_name ?? 'My Drupal Site', ENT_QUOTES, 'UTF-8');
$version = htmlspecialchars($drupal_version ?? '10.2.2', ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<meta name="Generator" content="Drupal 10 (https://www.drupal.org)">
<title>Administration | <?php echo $siteName; ?></title>
<style type="text/css">
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;font-size:14px;line-height:1.5;color:#232629;background:#f5f5f2}
a{color:#003cc5;text-decoration:none}
a:hover{color:#002e9a;text-decoration:underline}
#toolbar-bar{position:fixed;top:0;left:0;right:0;height:40px;background:#0f0f0f;z-index:999;display:flex;align-items:center;padding:0 12px}
#toolbar-bar a{color:#ddd;padding:8px 12px;font-size:14px;text-decoration:none}
#toolbar-bar a:hover{color:#fff;background:#333}
#toolbar-bar .home-link{font-weight:700}
.toolbar-tray{position:fixed;top:40px;left:0;bottom:0;width:240px;background:#fff;border-right:1px solid #bbb;overflow-y:auto;z-index:998}
.toolbar-tray .menu{list-style:none;padding:0;margin:0}
.toolbar-tray .menu li{border-bottom:1px solid #e6e6e6}
.toolbar-tray .menu li a{display:block;padding:10px 16px;color:#333;font-size:14px;text-decoration:none}
.toolbar-tray .menu li a:hover{background:#e7e7e6;color:#003cc5}
.toolbar-tray .menu li.is-active a{background:#e7f4fe;color:#003cc5;font-weight:600}
.main-content{margin-left:240px;padding:60px 30px 30px}
.main-content h1{font-size:24px;font-weight:700;margin-bottom:20px}
.admin-panel{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:20px;margin-top:20px}
.admin-block{background:#fff;border:1px solid #d3d4d9;border-radius:4px;padding:20px}
.admin-block h3{font-size:16px;margin-bottom:10px;color:#003cc5}
.admin-block p{font-size:13px;color:#57575d;margin-bottom:12px}
.admin-block ul{list-style:none;padding:0}
.admin-block li{padding:4px 0}
.admin-block li a{font-size:13px}
.status-report{background:#fff;border:1px solid #d3d4d9;border-radius:4px;padding:20px;margin-top:20px}
.status-report h2{font-size:18px;margin-bottom:12px}
.status-report table{width:100%;border-collapse:collapse}
.status-report th,.status-report td{text-align:left;padding:8px 12px;border-bottom:1px solid #e6e6e6;font-size:13px}
.status-report th{font-weight:600;background:#f5f5f2}
.status-ok{color:#28a745}
.status-warn{color:#ffc107}
.status-error{color:#d32f2f}
@media(max-width:768px){.toolbar-tray{width:60px}.toolbar-tray .menu li a{font-size:0;padding:12px}.main-content{margin-left:60px}}
</style>
</head>
<body>

<div id="toolbar-bar">
<a href="<?php echo $siteUrl; ?>/" class="home-link">Back to site</a>
<a href="<?php echo $siteUrl; ?>/admin">Manage</a>
<a href="<?php echo $siteUrl; ?>/admin/content">Content</a>
<a href="<?php echo $siteUrl; ?>/admin/structure">Structure</a>
<a href="<?php echo $siteUrl; ?>/admin/appearance">Appearance</a>
<a href="<?php echo $siteUrl; ?>/admin/modules">Extend</a>
<a href="<?php echo $siteUrl; ?>/admin/config">Configuration</a>
<a href="<?php echo $siteUrl; ?>/admin/people">People</a>
<a href="<?php echo $siteUrl; ?>/admin/reports">Reports</a>
<span style="flex:1"></span>
<a href="<?php echo $siteUrl; ?>/user/1">admin</a>
<a href="<?php echo $siteUrl; ?>/user/logout">Log out</a>
</div>

<div class="toolbar-tray">
<ul class="menu">
<li class="is-active"><a href="<?php echo $siteUrl; ?>/admin">Administration</a></li>
<li><a href="<?php echo $siteUrl; ?>/admin/content">Content</a></li>
<li><a href="<?php echo $siteUrl; ?>/admin/structure">Structure</a></li>
<li><a href="<?php echo $siteUrl; ?>/admin/appearance">Appearance</a></li>
<li><a href="<?php echo $siteUrl; ?>/admin/modules">Extend</a></li>
<li><a href="<?php echo $siteUrl; ?>/admin/config">Configuration</a></li>
<li><a href="<?php echo $siteUrl; ?>/admin/people">People</a></li>
<li><a href="<?php echo $siteUrl; ?>/admin/reports">Reports</a></li>
<li><a href="<?php echo $siteUrl; ?>/admin/help">Help</a></li>
</ul>
</div>

<div class="main-content">
<h1>Administration</h1>

<div class="admin-panel">
<div class="admin-block">
<h3><a href="<?php echo $siteUrl; ?>/admin/content">Content</a></h3>
<p>Find and manage content.</p>
<ul>
<li><a href="<?php echo $siteUrl; ?>/admin/content">Content overview</a></li>
<li><a href="<?php echo $siteUrl; ?>/admin/content/comment">Comments</a></li>
<li><a href="<?php echo $siteUrl; ?>/admin/content/files">Files</a></li>
</ul>
</div>
<div class="admin-block">
<h3><a href="<?php echo $siteUrl; ?>/admin/structure">Structure</a></h3>
<p>Administer content types, blocks, views, etc.</p>
<ul>
<li><a href="<?php echo $siteUrl; ?>/admin/structure/block">Block layout</a></li>
<li><a href="<?php echo $siteUrl; ?>/admin/structure/types">Content types</a></li>
<li><a href="<?php echo $siteUrl; ?>/admin/structure/menu">Menus</a></li>
<li><a href="<?php echo $siteUrl; ?>/admin/structure/taxonomy">Taxonomy</a></li>
<li><a href="<?php echo $siteUrl; ?>/admin/structure/views">Views</a></li>
</ul>
</div>
<div class="admin-block">
<h3><a href="<?php echo $siteUrl; ?>/admin/appearance">Appearance</a></h3>
<p>Select and configure your themes.</p>
</div>
<div class="admin-block">
<h3><a href="<?php echo $siteUrl; ?>/admin/modules">Extend</a></h3>
<p>Add and enable modules to extend site functionality.</p>
</div>
<div class="admin-block">
<h3><a href="<?php echo $siteUrl; ?>/admin/config">Configuration</a></h3>
<p>Administer settings.</p>
<ul>
<li><a href="<?php echo $siteUrl; ?>/admin/config/system/site-information">Site information</a></li>
<li><a href="<?php echo $siteUrl; ?>/admin/config/development/performance">Performance</a></li>
<li><a href="<?php echo $siteUrl; ?>/admin/config/development/logging">Logging and errors</a></li>
</ul>
</div>
<div class="admin-block">
<h3><a href="<?php echo $siteUrl; ?>/admin/people">People</a></h3>
<p>Manage user accounts, roles, and permissions.</p>
</div>
</div>

<div class="status-report">
<h2>Status report</h2>
<table>
<tr><th>Item</th><th>Status</th><th>Value</th></tr>
<tr><td>Drupal Version</td><td class="status-ok">OK</td><td><?php echo $version; ?></td></tr>
<tr><td>PHP</td><td class="status-ok">OK</td><td>8.2.14</td></tr>
<tr><td>Database</td><td class="status-ok">OK</td><td>MySQL 8.0.35</td></tr>
<tr><td>Web server</td><td class="status-ok">OK</td><td>Apache/2.4.58</td></tr>
<tr><td>Cron</td><td class="status-warn">Warning</td><td>Last run 3 hours ago</td></tr>
<tr><td>Module updates</td><td class="status-warn">Warning</td><td>2 updates available</td></tr>
<tr><td>Configuration</td><td class="status-ok">OK</td><td>Up to date</td></tr>
</table>
</div>
</div>

</body>
</html>
