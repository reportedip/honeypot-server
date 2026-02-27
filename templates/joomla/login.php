<?php
/**
 * Joomla administrator login form template.
 *
 * Variables: $site_name, $site_url, $joomla_version, $error, $username_value,
 *            Optional: $is_registration_page, $registration_success, $registration_message
 */

$siteUrl = htmlspecialchars($site_url ?? '', ENT_QUOTES, 'UTF-8');
$siteName = htmlspecialchars($site_name ?? 'My Joomla Site', ENT_QUOTES, 'UTF-8');
$version = htmlspecialchars($joomla_version ?? '4.4.2', ENT_QUOTES, 'UTF-8');
$errorMsg = $error ?? '';
$usernameVal = htmlspecialchars($username_value ?? '', ENT_QUOTES, 'UTF-8');
$isRegister = !empty($is_registration_page);
$regSuccess = !empty($registration_success);
$regMessage = $registration_message ?? '';
?>
<!DOCTYPE html>
<html lang="<?php echo htmlspecialchars($language ?? 'en-GB', ENT_QUOTES, 'UTF-8'); ?>" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title><?php echo $isRegister ? 'Create Account' : ($siteName . ' - Administration'); ?></title>
<style type="text/css">
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:"Roboto",-apple-system,BlinkMacSystemFont,"Segoe UI","Helvetica Neue",Arial,sans-serif;font-size:16px;line-height:1.5;background:#f0f4fb;min-height:100vh;display:flex;align-items:center;justify-content:center}
.login-wrapper{width:400px;max-width:90%;padding:20px}
.login-logo{text-align:center;margin-bottom:30px}
.login-logo svg{width:80px;height:80px}
.login-logo h1{font-size:18px;font-weight:400;color:#495057;margin-top:10px}
.login-card{background:#fff;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);padding:30px;margin-bottom:20px}
.login-card h2{font-size:20px;font-weight:600;color:#1d3557;margin-bottom:20px;text-align:center}
.form-group{margin-bottom:16px}
.form-group label{display:block;font-size:14px;font-weight:500;color:#495057;margin-bottom:6px}
.form-group input{width:100%;padding:10px 14px;border:1px solid #ced4da;border-radius:4px;font-size:15px;font-family:inherit;background:#fff;color:#212529;transition:border-color .15s}
.form-group input:focus{border-color:#457b9d;outline:0;box-shadow:0 0 0 3px rgba(69,123,157,0.25)}
.form-group select{width:100%;padding:10px 14px;border:1px solid #ced4da;border-radius:4px;font-size:15px;background:#fff}
.btn-login{width:100%;padding:12px;background:#457b9d;color:#fff;border:none;border-radius:4px;font-size:16px;font-weight:600;cursor:pointer;transition:background .15s}
.btn-login:hover{background:#1d3557}
.remember-me{display:flex;align-items:center;gap:8px;margin-bottom:16px;font-size:14px;color:#495057}
.remember-me input{margin:0}
.alert-error{background:#f8d7da;border:1px solid #f5c6cb;color:#721c24;padding:12px 16px;border-radius:4px;margin-bottom:16px;font-size:14px}
.alert-success{background:#d1e7dd;border:1px solid #badbcc;color:#0f5132;padding:12px 16px;border-radius:4px;margin-bottom:16px;font-size:14px}
.login-links{text-align:center;font-size:13px;color:#6c757d}
.login-links a{color:#457b9d}
.login-footer{text-align:center;font-size:12px;color:#adb5bd;margin-top:20px}
.login-footer a{color:#6c757d}
</style>
</head>
<body>

<div class="login-wrapper">
<div class="login-logo">
<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
<rect width="100" height="100" rx="20" fill="#1d3557"/>
<text x="50" y="65" text-anchor="middle" fill="#fff" font-size="40" font-weight="bold" font-family="Arial">J!</text>
</svg>
<h1><?php echo $siteName; ?></h1>
</div>

<?php if ($regSuccess): ?>
<div class="alert-success"><?php echo htmlspecialchars($regMessage, ENT_QUOTES, 'UTF-8'); ?></div>
<?php endif; ?>

<?php if ($errorMsg && !$isRegister): ?>
<div class="alert-error"><?php echo htmlspecialchars($errorMsg, ENT_QUOTES, 'UTF-8'); ?></div>
<?php endif; ?>

<div class="login-card">

<?php if ($isRegister && !$regSuccess): ?>
<h2>Create Account</h2>
<form method="post" action="<?php echo $siteUrl; ?>/index.php?option=com_users&task=registration.register">
<div class="form-group">
<label for="jform_name">Name</label>
<input type="text" id="jform_name" name="jform[name]" required>
</div>
<div class="form-group">
<label for="jform_username">Username</label>
<input type="text" id="jform_username" name="jform[username]" required>
</div>
<div class="form-group">
<label for="jform_email1">Email Address</label>
<input type="email" id="jform_email1" name="jform[email1]" required>
</div>
<div class="form-group">
<label for="jform_password1">Password</label>
<input type="password" id="jform_password1" name="jform[password1]" required>
</div>
<div class="form-group">
<label for="jform_password2">Confirm Password</label>
<input type="password" id="jform_password2" name="jform[password2]" required>
</div>
<button type="submit" class="btn-login">Register</button>
</form>

<?php else: ?>
<h2>Log in</h2>
<form method="post" action="<?php echo $siteUrl; ?>/administrator/index.php" id="form-login">
<div class="form-group">
<label for="mod-login-username">Username</label>
<input type="text" id="mod-login-username" name="username" autocomplete="username" value="<?php echo $usernameVal; ?>" required>
</div>
<div class="form-group">
<label for="mod-login-password">Password</label>
<input type="password" id="mod-login-password" name="passwd" autocomplete="current-password" required>
</div>
<div class="form-group">
<label for="lang">Language</label>
<select id="lang" name="lang">
<option value="">- Default -</option>
<option value="en-GB">English (en-GB)</option>
<option value="de-DE">German (de-DE)</option>
<option value="fr-FR">French (fr-FR)</option>
<option value="es-ES">Spanish (es-ES)</option>
</select>
</div>
<label class="remember-me"><input type="checkbox" name="remember" value="1"> Remember me</label>
<button type="submit" class="btn-login">Log in</button>
<input type="hidden" name="option" value="com_login">
<input type="hidden" name="task" value="login">
<input type="hidden" name="return" value="aW5kZXgucGhw">
</form>
<?php endif; ?>

</div>

<div class="login-links">
<a href="<?php echo $siteUrl; ?>/">Go to site home page</a>
<?php if (!$isRegister): ?>
| <a href="<?php echo $siteUrl; ?>/index.php?option=com_users&view=reset">Forgot your password?</a>
<?php else: ?>
| <a href="<?php echo $siteUrl; ?>/administrator">Log in</a>
<?php endif; ?>
</div>

<div class="login-footer">
<p>&copy; <?php echo date('Y'); ?> <?php echo $siteName; ?>. Powered by <a href="https://www.joomla.org">Joomla!</a> <?php echo $version; ?></p>
</div>
</div>

</body>
</html>
