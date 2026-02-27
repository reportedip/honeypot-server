<?php
/**
 * Joomla administrator control panel template.
 *
 * Variables: $site_name, $site_url, $joomla_version, $request_path
 */

$siteUrl = htmlspecialchars($site_url ?? '', ENT_QUOTES, 'UTF-8');
$siteName = htmlspecialchars($site_name ?? 'My Joomla Site', ENT_QUOTES, 'UTF-8');
$version = htmlspecialchars($joomla_version ?? '4.4.2', ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="en-GB" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Home Dashboard - <?php echo $siteName; ?> - Administration</title>
<style type="text/css">
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:"Roboto",-apple-system,BlinkMacSystemFont,"Segoe UI","Helvetica Neue",Arial,sans-serif;font-size:14px;line-height:1.5;color:#212529;background:#f0f4fb}
a{color:#457b9d;text-decoration:none}
a:hover{color:#1d3557}
.header{position:fixed;top:0;left:0;right:0;height:50px;background:#1d3557;z-index:999;display:flex;align-items:center;padding:0 16px}
.header .logo{color:#fff;font-weight:700;font-size:18px;margin-right:30px}
.header .logo span{color:#a8dadc}
.header nav a{color:#a8dadc;padding:14px 16px;font-size:14px;display:inline-block}
.header nav a:hover{color:#fff;background:rgba(255,255,255,0.1)}
.header .header-right{margin-left:auto;display:flex;align-items:center;gap:12px}
.header .header-right a{color:#a8dadc;font-size:13px}
.header .header-right a:hover{color:#fff}
.sidebar{position:fixed;top:50px;left:0;bottom:0;width:250px;background:#fff;border-right:1px solid #dee2e6;overflow-y:auto}
.sidebar .menu{list-style:none;padding:10px 0}
.sidebar .menu li{border-bottom:1px solid #f0f0f0}
.sidebar .menu li a{display:block;padding:10px 20px;color:#495057;font-size:14px}
.sidebar .menu li a:hover{background:#f0f4fb;color:#1d3557}
.sidebar .menu li.active a{background:#e7f1ff;color:#1d3557;font-weight:600;border-left:3px solid #457b9d}
.main-container{margin-left:250px;padding:70px 24px 24px}
.main-container h1{font-size:22px;font-weight:600;margin-bottom:20px;color:#1d3557}
.cpanel-modules{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:16px;margin-bottom:30px}
.cpanel-item{background:#fff;border:1px solid #dee2e6;border-radius:8px;padding:20px;text-align:center;transition:box-shadow .15s}
.cpanel-item:hover{box-shadow:0 2px 8px rgba(0,0,0,0.1)}
.cpanel-item .icon{font-size:36px;color:#457b9d;margin-bottom:8px}
.cpanel-item .title{font-size:14px;font-weight:500;color:#212529}
.cpanel-item .badge{display:inline-block;background:#dc3545;color:#fff;font-size:11px;padding:2px 8px;border-radius:10px;margin-left:4px}
.info-panels{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:20px;margin-top:20px}
.info-panel{background:#fff;border:1px solid #dee2e6;border-radius:8px;overflow:hidden}
.info-panel .panel-header{background:#f8f9fa;padding:12px 16px;border-bottom:1px solid #dee2e6;font-weight:600;font-size:15px;color:#1d3557}
.info-panel .panel-body{padding:16px}
.info-panel table{width:100%;border-collapse:collapse;font-size:13px}
.info-panel th,.info-panel td{text-align:left;padding:6px 8px;border-bottom:1px solid #f0f0f0}
.info-panel th{font-weight:600;color:#495057}
.footer{position:fixed;bottom:0;left:250px;right:0;padding:8px 16px;background:#f8f9fa;border-top:1px solid #dee2e6;font-size:12px;color:#6c757d}
.footer a{color:#457b9d}
@media(max-width:768px){.sidebar{width:60px}.sidebar .menu li a{font-size:0;padding:14px}.main-container{margin-left:60px}.footer{left:60px}}
</style>
</head>
<body>

<div class="header">
<div class="logo"><span>J!</span> <?php echo $siteName; ?></div>
<nav>
<a href="<?php echo $siteUrl; ?>/administrator/index.php">System</a>
<a href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_content">Content</a>
<a href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_menus">Menus</a>
<a href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_modules">Extensions</a>
<a href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_users">Users</a>
</nav>
<div class="header-right">
<a href="<?php echo $siteUrl; ?>/" title="Preview site">Visit Site</a>
<a href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_admin&task=profile.edit">Super User</a>
<a href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_login&task=logout">Logout</a>
</div>
</div>

<div class="sidebar">
<ul class="menu">
<li class="active"><a href="<?php echo $siteUrl; ?>/administrator/">Home Dashboard</a></li>
<li><a href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_cpanel&view=cpanel&dashboard=system">System Dashboard</a></li>
<li><a href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_config">Global Configuration</a></li>
<li><a href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_checkin">Global Check-in</a></li>
<li><a href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_cache">Clear Cache</a></li>
<li><a href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_installer">Install Extensions</a></li>
<li><a href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_installer&view=update">Update Extensions</a></li>
<li><a href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_installer&view=languages">Install Languages</a></li>
</ul>
</div>

<div class="main-container">
<h1>Home Dashboard</h1>

<div class="cpanel-modules">
<a class="cpanel-item" href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_content">
<div class="icon">&#128196;</div>
<div class="title">Articles</div>
</a>
<a class="cpanel-item" href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_categories">
<div class="icon">&#128193;</div>
<div class="title">Categories</div>
</a>
<a class="cpanel-item" href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_media">
<div class="icon">&#127748;</div>
<div class="title">Media</div>
</a>
<a class="cpanel-item" href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_modules">
<div class="icon">&#128230;</div>
<div class="title">Modules</div>
</a>
<a class="cpanel-item" href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_users">
<div class="icon">&#128101;</div>
<div class="title">Users</div>
</a>
<a class="cpanel-item" href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_menus">
<div class="icon">&#9776;</div>
<div class="title">Menus</div>
</a>
<a class="cpanel-item" href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_plugins">
<div class="icon">&#128268;</div>
<div class="title">Plugins</div>
</a>
<a class="cpanel-item" href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_templates">
<div class="icon">&#127912;</div>
<div class="title">Templates</div>
</a>
<a class="cpanel-item" href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_languages">
<div class="icon">&#127760;</div>
<div class="title">Languages</div>
</a>
<a class="cpanel-item" href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_installer&view=update">
<div class="icon">&#128260;</div>
<div class="title">Updates <span class="badge">2</span></div>
</a>
</div>

<div class="info-panels">
<div class="info-panel">
<div class="panel-header">Site Information</div>
<div class="panel-body">
<table>
<tr><th>PHP</th><td>8.2.14</td></tr>
<tr><th>Database</th><td>MySQL 8.0.35-0ubuntu0.22.04.1</td></tr>
<tr><th>Joomla! Version</th><td><?php echo $version; ?> Stable</td></tr>
<tr><th>Web Server</th><td>Apache/2.4.58</td></tr>
<tr><th>PHP Memory Limit</th><td>256M</td></tr>
<tr><th>Configuration File</th><td>Writable</td></tr>
</table>
</div>
</div>

<div class="info-panel">
<div class="panel-header">Logged-in Users</div>
<div class="panel-body">
<table>
<tr><th>Name</th><th>Location</th><th>Last Activity</th></tr>
<tr><td>Super User</td><td>Administrator</td><td><?php echo date('H:i'); ?></td></tr>
</table>
</div>
</div>

<div class="info-panel">
<div class="panel-header">Recently Added Articles</div>
<div class="panel-body">
<table>
<tr><th>Title</th><th>Date</th><th>Author</th></tr>
<tr><td><a href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_content&task=article.edit&id=3">Latest News and Announcements</a></td><td>Feb 5, 2024</td><td>Super User</td></tr>
<tr><td><a href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_content&task=article.edit&id=2">Our Services</a></td><td>Jan 20, 2024</td><td>Super User</td></tr>
<tr><td><a href="<?php echo $siteUrl; ?>/administrator/index.php?option=com_content&task=article.edit&id=1">Welcome</a></td><td>Jan 15, 2024</td><td>Super User</td></tr>
</table>
</div>
</div>

<div class="info-panel">
<div class="panel-header">Popular Articles</div>
<div class="panel-body">
<table>
<tr><th>Title</th><th>Hits</th></tr>
<tr><td>Welcome to <?php echo $siteName; ?></td><td>1,247</td></tr>
<tr><td>Our Services</td><td>853</td></tr>
<tr><td>Latest News and Announcements</td><td>412</td></tr>
</table>
</div>
</div>
</div>

</div>

<div class="footer">
Joomla! <?php echo $version; ?> Stable <a href="https://www.joomla.org">Joomla!</a> is free software released under the GNU General Public License.
</div>

</body>
</html>
