<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;">
    <title>Login - ReportedIP Honeypot</title>
    <style>
        :root {
            --rip-primary: #4F46E5;
            --rip-primary-hover: #4338CA;
            --rip-gray-300: #D1D5DB;
            --rip-gray-500: #6B7280;
            --rip-gray-800: #1F2937;
            --rip-gray-900: #111827;
            --rip-danger-light: #FEF2F2;
            --rip-danger-text: #991B1B;
            --rip-danger-border: #FECACA;
            --rip-radius-md: 6px;
            --rip-radius-xl: 10px;
            --rip-transition: 0.15s ease;
            --rip-font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: var(--rip-font-family);
            background: linear-gradient(135deg, var(--rip-gray-900) 0%, var(--rip-gray-800) 50%, var(--rip-primary) 100%);
            display: flex; justify-content: center; align-items: center; min-height: 100vh;
        }
        .rip-login {
            background: #fff; border-radius: var(--rip-radius-xl);
            box-shadow: 0 8px 32px rgba(0,0,0,0.3); padding: 40px;
            width: 100%; max-width: 380px;
        }
        .rip-login__brand {
            text-align: center; margin-bottom: 20px;
            display: flex; justify-content: center;
        }
        .rip-login__title { font-size: 20px; font-weight: 700; color: var(--rip-gray-900); text-align: center; margin-bottom: 6px; }
        .rip-login__subtitle { font-size: 13px; color: var(--rip-gray-500); text-align: center; margin-bottom: 28px; }
        .rip-login__error {
            background: var(--rip-danger-light); color: var(--rip-danger-text);
            border: 1px solid var(--rip-danger-border); padding: 10px 14px;
            border-radius: var(--rip-radius-md); font-size: 13px; margin-bottom: 18px; text-align: center;
        }
        .rip-form-group { margin-bottom: 18px; }
        .rip-label { display: block; font-size: 13px; font-weight: 600; color: var(--rip-gray-500); margin-bottom: 6px; }
        .rip-input {
            width: 100%; padding: 10px 14px; border: 1px solid var(--rip-gray-300); border-radius: var(--rip-radius-md);
            font-size: 14px; background: #F9FAFB; transition: border-color var(--rip-transition);
        }
        .rip-input:focus { outline: none; border-color: var(--rip-primary); box-shadow: 0 0 0 3px rgba(79,70,229,0.15); }
        .rip-button--login {
            width: 100%; padding: 11px; background: var(--rip-primary); color: #fff; border: none;
            border-radius: var(--rip-radius-md); font-size: 14px; font-weight: 600; cursor: pointer;
            transition: background var(--rip-transition);
        }
        .rip-button--login:hover { background: var(--rip-primary-hover); }
        .rip-trust-badges {
            display: flex; align-items: center; justify-content: center; gap: 16px;
            padding: 16px 0 0; margin-top: 24px; border-top: 1px solid #E5E7EB; flex-wrap: wrap;
        }
        .rip-trust-badge { display: inline-flex; align-items: center; gap: 4px; font-size: 10px; color: #9CA3AF; font-weight: 500; }
        .rip-trust-badge svg { width: 12px; height: 12px; }
    </style>
</head>
<body>
    <div class="rip-login">
        <div class="rip-login__brand">
            <svg width="44" height="44" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M16 2L4 8v8c0 7.73 5.12 14.96 12 16.8C22.88 30.96 28 23.73 28 16V8L16 2z" fill="#4F46E5" opacity="0.15"/>
                <path d="M16 2L4 8v8c0 7.73 5.12 14.96 12 16.8C22.88 30.96 28 23.73 28 16V8L16 2z" stroke="#4F46E5" stroke-width="1.5" fill="none"/>
                <path d="M12 16l3 3 5-6" stroke="#4F46E5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
            </svg>
        </div>
        <h1 class="rip-login__title">ReportedIP Honeypot</h1>
        <p class="rip-login__subtitle">Enter your admin password to continue.</p>

        <?php if (!empty($error)): ?>
            <div class="rip-login__error"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
        <?php endif; ?>

        <form method="post" action="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/login">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token ?? '', ENT_QUOTES, 'UTF-8') ?>">
            <div class="rip-form-group">
                <label class="rip-label" for="password">Password</label>
                <input class="rip-input" type="password" id="password" name="password" required autofocus placeholder="Admin password">
            </div>
            <button type="submit" class="rip-button--login">Log In</button>
        </form>

        <div class="rip-trust-badges">
            <span class="rip-trust-badge">
                <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 1a2 2 0 0 1 2 2v4H6V3a2 2 0 0 1 2-2zm3 6V3a3 3 0 0 0-6 0v4a2 2 0 0 0-2 2v4a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2z"/></svg>
                Security Focused
            </span>
            <span class="rip-trust-badge">
                <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 0a8 8 0 1 0 0 16A8 8 0 0 0 8 0zm3.5 7.5h-3v3a.5.5 0 0 1-1 0v-3h-3a.5.5 0 0 1 0-1h3v-3a.5.5 0 0 1 1 0v3h3a.5.5 0 0 1 0 1z"/></svg>
                GDPR Compliant
            </span>
            <span class="rip-trust-badge">
                <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 1L1 5v6l7 4 7-4V5L8 1zm0 1.2L13.5 5.5 8 8.8 2.5 5.5 8 2.2zM2 6.3l5.5 3.1v4.3L2 10.6V6.3zm7 7.4V9.4L14 6.3v4.3L9 13.7z"/></svg>
                Made in Germany
            </span>
        </div>
    </div>
</body>
</html>
