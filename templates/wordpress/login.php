<?php
/**
 * WordPress login page template.
 *
 * Variables: $site_name, $site_url, $wp_version, $error, $username_value,
 *            Optional: $is_registration_page, $registration_success, $registration_message
 */

$siteUrl = htmlspecialchars($site_url ?? '', ENT_QUOTES, 'UTF-8');
$siteName = htmlspecialchars($site_name ?? 'My WordPress Site', ENT_QUOTES, 'UTF-8');
$errorMsg = $error ?? '';
$usernameVal = htmlspecialchars($username_value ?? '', ENT_QUOTES, 'UTF-8');
$isRegister = !empty($is_registration_page);
$regSuccess = !empty($registration_success);
$regMessage = $registration_message ?? '';
?>
<!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="max-image-preview:large, noindex, noarchive, nofollow">
<title><?php echo $isRegister ? 'Registration Form' : ($siteName . ' &rsaquo; Log In'); ?></title>
<style type="text/css">
*{box-sizing:border-box}
body{background:#f0f0f1;min-width:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif;font-size:13px;line-height:1.4;color:#3c434a}
a{color:#2271b1;text-decoration:none}
a:hover{color:#135e96}
#login{width:320px;padding:5% 0 0;margin:auto}
#login h1{text-align:center;margin-bottom:24px}
#login h1 a{display:inline-block;background-image:url('data:image/svg+xml;charset=utf-8,%3Csvg xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22 viewBox%3D%220 0 120 120%22%3E%3Cpath fill%3D%22%233858e9%22 d%3D%22M60 0C27 0 0 27 0 60s27 60 60 60 60-27 60-60S93 0 60 0zM17.6 60c0-5.7 1.1-11.2 3.1-16.2l17.2 47.1C26.5 84.4 17.6 73.2 17.6 60zm42.4 42.4c-4.3 0-8.5-.7-12.4-1.9l13.2-38.3 13.5 37c.1.2.2.4.3.5-4.5 1.7-9.5 2.7-14.6 2.7zm6.1-62.3c2.6-.1 5-.4 5-.4 2.4-.3 2.1-3.7-.3-3.6 0 0-7.1.6-11.7.6-4.3 0-11.5-.6-11.5-.6-2.4-.1-2.6 3.5-.3 3.6 0 0 2.2.3 4.6.4l6.8 18.6-9.6 28.7L35.7 40.1c2.6-.1 5-.4 5-.4 2.4-.3 2.1-3.7-.3-3.6 0 0-7.1.6-11.7.6-.8 0-1.8 0-2.8-.1C32.4 25.7 45.2 17.6 60 17.6c11 0 21.1 4.2 28.6 11.2-.2 0-.4 0-.5 0-4.3 0-7.3 3.7-7.3 7.7 0 3.6 2.1 6.6 4.3 10.2 1.7 2.9 3.6 6.7 3.6 12.1 0 3.7-1.4 8.1-3.4 14.1l-4.4 14.7-15.8-47.3zm16.2 55.6l13.4-38.8c2.5-6.3 3.3-11.3 3.3-15.8 0-1.6-.1-3.1-.3-4.6 3.4 6.3 5.4 13.5 5.4 21.2 0 16.4-8.9 30.7-22.1 38.4-.1-.1-.2-.3.3-0.4z%22%2F%3E%3C%2Fsvg%3E');background-size:84px;background-position:center;background-repeat:no-repeat;width:84px;height:84px;text-indent:-9999px;overflow:hidden;outline:0}
.login form{margin-top:20px;margin-left:0;padding:26px 24px 34px;font-weight:400;overflow:hidden;background:#fff;border:1px solid #c3c4c7;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
.login label{font-size:14px;line-height:1.5;display:block;margin-bottom:3px}
.login input[type="text"],
.login input[type="password"],
.login input[type="email"]{font-size:24px;width:100%;padding:3px;margin:2px 6px 16px 0;border:1px solid #8c8f94;border-radius:4px;background:#fff;color:#2c3338;line-height:1.33;font-family:inherit}
.login input[type="text"]:focus,
.login input[type="password"]:focus,
.login input[type="email"]:focus{border-color:#2271b1;box-shadow:0 0 0 1px #2271b1;outline:2px solid transparent}
.login .forgetmenot{float:left;margin-bottom:0}
.login .forgetmenot label{font-size:12px;display:inline-flex;align-items:center}
.login .forgetmenot input{margin:0 6px 0 0}
.submit .button-primary{float:right;padding:0 12px;min-height:32px;background:#2271b1;border-color:#2271b1;color:#fff;font-size:13px;line-height:2.15;border-radius:3px;border:1px solid;cursor:pointer;text-decoration:none;text-shadow:none}
.submit .button-primary:hover{background:#135e96;border-color:#135e96}
#login_error{border-left:4px solid #d63638;padding:12px;margin-bottom:16px;background:#fff;border-radius:0 4px 4px 0;box-shadow:0 1px 1px rgba(0,0,0,.04)}
.message{border-left:4px solid #00a32a;padding:12px;margin-bottom:16px;background:#fff;border-radius:0 4px 4px 0;box-shadow:0 1px 1px rgba(0,0,0,.04)}
#nav,#backtoblog{font-size:13px;padding:0 24px 0;margin:16px 0}
#nav a,#backtoblog a{color:#50575e}
#nav a:hover,#backtoblog a:hover{color:#2271b1}
.privacy-policy-page-link{text-align:center;margin-top:20px}
.privacy-policy-page-link a{font-size:12px;color:#50575e}
.clear{clear:both}
</style>
</head>
<body class="login wp-core-ui">
<div id="login">
<h1><a href="https://wordpress.org/" title="Powered by WordPress"><?php echo $siteName; ?></a></h1>

<?php if ($regSuccess): ?>
<p class="message"><?php echo htmlspecialchars($regMessage, ENT_QUOTES, 'UTF-8'); ?></p>
<?php endif; ?>

<?php if ($errorMsg && !$isRegister): ?>
<div id="login_error"><?php echo $errorMsg; ?></div>
<?php endif; ?>

<?php if ($isRegister && !$regSuccess): ?>
<form name="registerform" id="registerform" action="<?php echo $siteUrl; ?>/wp-login.php?action=register" method="post" novalidate="novalidate">
<p>
<label for="user_login">Username</label>
<input type="text" name="user_login" id="user_login" autocapitalize="none" autocomplete="username" maxlength="60" value="">
</p>
<p>
<label for="user_email">Email</label>
<input type="email" name="user_email" id="user_email" autocomplete="email" maxlength="100" value="">
</p>
<p id="reg_passmail">Registration confirmation will be emailed to you.</p>
<br class="clear">
<input type="hidden" name="redirect_to" value="">
<p class="submit">
<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Register">
</p>
</form>
<p id="nav">
<a href="<?php echo $siteUrl; ?>/wp-login.php">Log in</a> |
<a href="<?php echo $siteUrl; ?>/wp-login.php?action=lostpassword">Lost your password?</a>
</p>

<?php else: ?>
<form name="loginform" id="loginform" action="<?php echo $siteUrl; ?>/wp-login.php" method="post">
<p>
<label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" autocomplete="username" value="<?php echo $usernameVal; ?>" size="20" autocapitalize="off" required>
</p>
<p>
<label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass" autocomplete="current-password" spellcheck="false" value="" size="20" required>
</p>
<p class="forgetmenot"><label><input name="rememberme" type="checkbox" id="rememberme" value="forever"> Remember Me</label></p>
<p class="submit">
<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In">
<input type="hidden" name="redirect_to" value="<?php echo $siteUrl; ?>/wp-admin/">
<input type="hidden" name="testcookie" value="1">
</p>
</form>
<p id="nav">
<a href="<?php echo $siteUrl; ?>/wp-login.php?action=lostpassword">Lost your password?</a>
</p>
<?php endif; ?>

<p id="backtoblog">
<a href="<?php echo $siteUrl; ?>/">&larr; Go to <?php echo $siteName; ?></a>
</p>

<div class="privacy-policy-page-link">
<a href="<?php echo $siteUrl; ?>/privacy-policy/">Privacy Policy</a>
</div>

</div>

</body>
</html>
