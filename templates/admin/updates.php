<?php
/**
 * Admin Updates Template
 *
 * Variables: $update_status, $current_version, $preflight, $backups,
 *            $admin_path, $csrf_token, $message, $message_type
 */

$page_title = 'Updates';
$active_tab = 'updates';

$status = $update_status ?? [];
$updateAvailable = $status['update_available'] ?? false;
$latestVersion = $status['latest_version'] ?? '';
$lastCheckTime = $status['last_check_time'] ?? null;
$autoUpdateEnabled = $status['auto_update_enabled'] ?? true;
$updateInProgress = ($status['update_in_progress'] ?? false);
$releaseNotes = $status['latest_release_notes'] ?? '';
$publishedAt = $status['latest_published_at'] ?? '';
$history = $status['history'] ?? [];
$errors = $status['errors'] ?? [];

$checks = $preflight['checks'] ?? [];
$preflightOk = $preflight['ok'] ?? false;

ob_start();
?>

<!-- Version Status Card -->
<div class="rip-card">
    <div class="rip-card__header">
        Version Status
        <?php if ($updateInProgress): ?>
            <span class="rip-badge" style="margin-left:8px; background:var(--rip-warning); color:#fff;">In Progress</span>
        <?php elseif ($updateAvailable): ?>
            <span class="rip-badge" style="margin-left:8px; background:var(--rip-warning); color:#fff;">Update Available</span>
        <?php else: ?>
            <span class="rip-badge rip-badge--sent" style="margin-left:8px;">Up to Date</span>
        <?php endif; ?>
    </div>

    <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:16px; margin-bottom:20px;">
        <div>
            <div style="font-size:var(--rip-font-size-xs); color:var(--rip-gray-500); text-transform:uppercase; letter-spacing:0.3px; margin-bottom:4px;">Current Version</div>
            <div style="font-size:var(--rip-font-size-2xl); font-weight:700; color:var(--rip-gray-900);">v<?= htmlspecialchars($current_version ?? 'unknown', ENT_QUOTES, 'UTF-8') ?></div>
        </div>
        <?php if ($updateAvailable && $latestVersion !== ''): ?>
        <div>
            <div style="font-size:var(--rip-font-size-xs); color:var(--rip-gray-500); text-transform:uppercase; letter-spacing:0.3px; margin-bottom:4px;">Latest Version</div>
            <div style="font-size:var(--rip-font-size-2xl); font-weight:700; color:var(--rip-success);">v<?= htmlspecialchars($latestVersion, ENT_QUOTES, 'UTF-8') ?></div>
        </div>
        <?php endif; ?>
        <div>
            <div style="font-size:var(--rip-font-size-xs); color:var(--rip-gray-500); text-transform:uppercase; letter-spacing:0.3px; margin-bottom:4px;">Last Check</div>
            <div style="font-size:var(--rip-font-size-md); font-weight:500; color:var(--rip-gray-700);"><?= htmlspecialchars($lastCheckTime ?? 'Never', ENT_QUOTES, 'UTF-8') ?></div>
        </div>
    </div>

    <!-- Action Buttons -->
    <div style="display:flex; gap:10px; flex-wrap:wrap; align-items:center;">
        <form method="post" action="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/updates/check" style="margin:0;">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token ?? '', ENT_QUOTES, 'UTF-8') ?>">
            <button type="submit" class="rip-button rip-button--secondary">Check Now</button>
        </form>

        <?php if ($updateAvailable && !$updateInProgress): ?>
        <form method="post" action="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/updates/apply" style="margin:0;">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token ?? '', ENT_QUOTES, 'UTF-8') ?>">
            <button type="submit" class="rip-button rip-button--primary" onclick="return confirm('Apply update to v<?= htmlspecialchars($latestVersion, ENT_QUOTES, 'UTF-8') ?>? A backup will be created automatically.');">Update to v<?= htmlspecialchars($latestVersion, ENT_QUOTES, 'UTF-8') ?></button>
        </form>
        <?php endif; ?>

        <form method="post" action="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/updates/toggle-auto" style="margin:0; margin-left:auto;">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token ?? '', ENT_QUOTES, 'UTF-8') ?>">
            <label class="rip-toggle">
                <input type="checkbox" class="rip-toggle__input" <?= $autoUpdateEnabled ? 'checked' : '' ?> onchange="this.form.submit();">
                <span class="rip-toggle__slider"></span>
                <span class="rip-toggle__label">Auto-Update</span>
            </label>
        </form>
    </div>
</div>

<!-- Release Notes (only when update available) -->
<?php if ($updateAvailable && $releaseNotes !== ''): ?>
<div class="rip-card">
    <div class="rip-card__header">
        Release Notes &mdash; v<?= htmlspecialchars($latestVersion, ENT_QUOTES, 'UTF-8') ?>
        <?php if ($publishedAt !== ''): ?>
            <span style="float:right; font-weight:400; font-size:var(--rip-font-size-sm); color:var(--rip-gray-400);">
                <?= htmlspecialchars(substr($publishedAt, 0, 10), ENT_QUOTES, 'UTF-8') ?>
            </span>
        <?php endif; ?>
    </div>
    <div style="font-size:var(--rip-font-size-base); line-height:1.7; color:var(--rip-gray-700); white-space:pre-line;"><?= htmlspecialchars($releaseNotes, ENT_QUOTES, 'UTF-8') ?></div>
</div>
<?php endif; ?>

<!-- System Check Card -->
<div class="rip-card">
    <div class="rip-card__header">
        System Check
        <?php if ($preflightOk): ?>
            <span class="rip-badge rip-badge--sent" style="margin-left:8px;">All OK</span>
        <?php else: ?>
            <span class="rip-badge" style="margin-left:8px; background:var(--rip-danger-light); color:var(--rip-danger-text);">Issues Found</span>
        <?php endif; ?>
    </div>
    <div style="display:flex; flex-direction:column; gap:8px;">
        <?php foreach ($checks as $checkName => $check): ?>
            <div style="display:flex; justify-content:space-between; align-items:center; padding:6px 0; border-bottom:1px solid var(--rip-gray-100);">
                <span style="font-size:var(--rip-font-size-base); color:var(--rip-gray-700);"><?= htmlspecialchars($check['message'], ENT_QUOTES, 'UTF-8') ?></span>
                <?php if ($check['ok']): ?>
                    <span style="color:var(--rip-success); font-weight:600; font-size:var(--rip-font-size-sm);">OK</span>
                <?php else: ?>
                    <span style="color:var(--rip-danger); font-weight:600; font-size:var(--rip-font-size-sm);">FAIL</span>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
    </div>
</div>

<!-- Update History -->
<?php if (!empty($history)): ?>
<div class="rip-card">
    <div class="rip-card__header">Update History</div>
    <div style="overflow-x:auto;">
        <table class="rip-table">
            <thead>
                <tr>
                    <th>Date</th>
                    <th>From</th>
                    <th>To</th>
                    <th>Status</th>
                    <th>Message</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach (array_slice($history, 0, 20) as $entry): ?>
                    <tr>
                        <td style="white-space:nowrap; font-size:var(--rip-font-size-sm); color:var(--rip-gray-500);"><?= htmlspecialchars($entry['time'] ?? '', ENT_QUOTES, 'UTF-8') ?></td>
                        <td><span class="rip-badge rip-badge--method"><?= htmlspecialchars($entry['from_version'] ?? '', ENT_QUOTES, 'UTF-8') ?></span></td>
                        <td><span class="rip-badge rip-badge--method"><?= htmlspecialchars($entry['to_version'] ?? '', ENT_QUOTES, 'UTF-8') ?></span></td>
                        <td>
                            <?php if ($entry['success'] ?? false): ?>
                                <span class="rip-badge rip-badge--sent">Success</span>
                            <?php else: ?>
                                <span class="rip-badge rip-badge--pending">Failed</span>
                            <?php endif; ?>
                        </td>
                        <td style="max-width:300px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:var(--rip-font-size-sm); color:var(--rip-gray-500);" title="<?= htmlspecialchars($entry['message'] ?? '', ENT_QUOTES, 'UTF-8') ?>">
                            <?= htmlspecialchars($entry['message'] ?? '', ENT_QUOTES, 'UTF-8') ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>
<?php endif; ?>

<!-- Backup Management -->
<div class="rip-card">
    <div class="rip-card__header">Backup Management</div>
    <?php if (!empty($backups)): ?>
        <div style="overflow-x:auto;">
            <table class="rip-table">
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Version</th>
                        <th>Size</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($backups as $backup): ?>
                        <tr>
                            <td style="white-space:nowrap; font-size:var(--rip-font-size-sm); color:var(--rip-gray-500);"><?= htmlspecialchars($backup['timestamp'] ?? '', ENT_QUOTES, 'UTF-8') ?></td>
                            <td><span class="rip-badge rip-badge--method"><?= htmlspecialchars($backup['version'] ?? '', ENT_QUOTES, 'UTF-8') ?></span></td>
                            <td style="font-size:var(--rip-font-size-sm); color:var(--rip-gray-500);"><?= htmlspecialchars($backup['size'] ?? '', ENT_QUOTES, 'UTF-8') ?></td>
                            <td>
                                <form method="post" action="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/updates/rollback" style="display:inline;">
                                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token ?? '', ENT_QUOTES, 'UTF-8') ?>">
                                    <input type="hidden" name="backup_name" value="<?= htmlspecialchars($backup['name'] ?? '', ENT_QUOTES, 'UTF-8') ?>">
                                    <button type="submit" class="rip-button rip-button--sm rip-button--secondary" onclick="return confirm('Restore backup from <?= htmlspecialchars($backup['timestamp'] ?? '', ENT_QUOTES, 'UTF-8') ?>? This will overwrite current application files.');">Restore</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php else: ?>
        <div class="rip-empty-state">
            <div class="rip-empty-state__icon">&#128230;</div>
            <div class="rip-empty-state__title">No Backups</div>
            <div class="rip-empty-state__text">Backups are created automatically before each update.</div>
        </div>
    <?php endif; ?>
</div>

<!-- Recent Errors -->
<?php if (!empty($errors)): ?>
<div class="rip-card">
    <div class="rip-card__header">Recent Errors</div>
    <div style="overflow-x:auto;">
        <table class="rip-table">
            <thead>
                <tr>
                    <th>Date</th>
                    <th>Message</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach (array_slice($errors, 0, 10) as $error): ?>
                    <tr>
                        <td style="white-space:nowrap; font-size:var(--rip-font-size-sm); color:var(--rip-gray-500);"><?= htmlspecialchars($error['time'] ?? '', ENT_QUOTES, 'UTF-8') ?></td>
                        <td style="font-size:var(--rip-font-size-sm); color:var(--rip-danger-text);"><?= htmlspecialchars($error['message'] ?? '', ENT_QUOTES, 'UTF-8') ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>
<?php endif; ?>

<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
?>
