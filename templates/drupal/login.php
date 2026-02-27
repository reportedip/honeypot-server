<?php
/**
 * Drupal login form template.
 *
 * Variables: $site_name, $site_url, $drupal_version, $error, $username_value,
 *            Optional: $is_registration_page, $registration_success, $registration_message
 */

$siteUrl = htmlspecialchars($site_url ?? '', ENT_QUOTES, 'UTF-8');
$siteName = htmlspecialchars($site_name ?? 'My Drupal Site', ENT_QUOTES, 'UTF-8');
$errorMsg = $error ?? '';
$usernameVal = htmlspecialchars($username_value ?? '', ENT_QUOTES, 'UTF-8');
$isRegister = !empty($is_registration_page);
$regSuccess = !empty($registration_success);
$regMessage = $registration_message ?? '';
?>
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="Generator" content="Drupal 10 (https://www.drupal.org)">
<title><?php echo $isRegister ? 'Create new account' : 'Log in'; ?> | <?php echo $siteName; ?></title>
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
.page-content{max-width:600px;margin:40px auto;padding:0 20px}
.login-form{background:#fff;padding:30px;border:1px solid #d3d4d9;border-radius:4px}
.login-form h1{font-size:24px;margin-bottom:20px;font-weight:700}
.form-item{margin-bottom:16px}
.form-item label{display:block;font-weight:700;margin-bottom:4px;font-size:14px}
.form-item input[type="text"],
.form-item input[type="password"],
.form-item input[type="email"]{width:100%;padding:10px;border:1px solid #8e929c;font-size:16px;border-radius:4px;font-family:inherit}
.form-item input:focus{border-color:#003cc5;outline:2px solid rgba(0,60,197,0.3)}
.form-item .description{font-size:13px;color:#57575d;margin-top:4px}
.form-actions{margin-top:20px}
.form-actions button{padding:10px 24px;background:#003cc5;color:#fff;border:none;font-size:16px;border-radius:4px;cursor:pointer;font-weight:600}
.form-actions button:hover{background:#002e9a}
.messages--error{background:#fce4ec;border:1px solid #d32f2f;border-left:4px solid #d32f2f;padding:12px 16px;margin-bottom:20px;color:#b71c1c;border-radius:4px;font-size:14px}
.messages--status{background:#d4edda;border:1px solid #c3e6cb;border-left:4px solid #28a745;padding:12px 16px;margin-bottom:20px;color:#155724;border-radius:4px;font-size:14px}
.form-links{margin-top:16px;font-size:14px}
.form-links a{margin-right:12px}
footer.site-footer{background:#1b1b1b;color:#929296;text-align:center;padding:20px;font-size:13px;position:fixed;bottom:0;left:0;right:0}
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

<?php if ($regSuccess): ?>
<div class="messages--status"><?php echo htmlspecialchars($regMessage, ENT_QUOTES, 'UTF-8'); ?></div>
<?php endif; ?>

<?php if ($errorMsg && !$isRegister): ?>
<div class="messages--error"><?php echo $errorMsg; ?></div>
<?php endif; ?>

<div class="login-form">

<?php if ($isRegister && !$regSuccess): ?>
<h1>Create new account</h1>
<form method="post" action="<?php echo $siteUrl; ?>/user/register">
<div class="form-item">
<label for="edit-name">Username <span style="color:#d32f2f">*</span></label>
<input type="text" id="edit-name" name="name" maxlength="60" autocorrect="none" autocapitalize="none" spellcheck="false" required>
<div class="description">Several special characters are allowed, including space, period (.), hyphen (-), apostrophe ('), underscore (_), and the @ sign.</div>
</div>
<div class="form-item">
<label for="edit-mail">Email address <span style="color:#d32f2f">*</span></label>
<input type="email" id="edit-mail" name="mail" maxlength="254" required>
<div class="description">A valid email address. All emails from the system will be sent to this address.</div>
</div>
<div class="form-actions">
<button type="submit">Create new account</button>
</div>
</form>
<div class="form-links">
<a href="<?php echo $siteUrl; ?>/user/login">Log in</a>
<a href="<?php echo $siteUrl; ?>/user/password">Reset your password</a>
</div>

<?php else: ?>
<h1>Log in</h1>
<form method="post" action="<?php echo $siteUrl; ?>/user/login">
<div class="form-item">
<label for="edit-name">Username <span style="color:#d32f2f">*</span></label>
<input type="text" id="edit-name" name="name" maxlength="60" autocorrect="none" autocapitalize="none" spellcheck="false" value="<?php echo $usernameVal; ?>" required>
</div>
<div class="form-item">
<label for="edit-pass">Password <span style="color:#d32f2f">*</span></label>
<input type="password" id="edit-pass" name="pass" required>
</div>
<div class="form-actions">
<button type="submit">Log in</button>
</div>
</form>
<div class="form-links">
<a href="<?php echo $siteUrl; ?>/user/register">Create new account</a>
<a href="<?php echo $siteUrl; ?>/user/password">Reset your password</a>
</div>
<?php endif; ?>

</div>
</div>

<footer class="site-footer">
<p>Powered by <a href="https://www.drupal.org">Drupal</a></p>
</footer>

</body>
</html>
