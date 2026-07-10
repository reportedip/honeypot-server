<?php
/**
 * Admin Threat Intel Template
 *
 * Variables: $summary, $tab, $tokens, $captures, $admin_path, $csrf_token
 */

$page_title = 'Threat Intel';
$active_tab = 'intel';

/** Human-readable size. */
$fmtSize = static function (int $bytes): string {
    if ($bytes < 1024) {
        return $bytes . ' B';
    }
    if ($bytes < 1048576) {
        return round($bytes / 1024, 1) . ' KB';
    }
    return round($bytes / 1048576, 2) . ' MB';
};

$base = htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8');

ob_start();
?>

<!-- Explainer -->
<details class="rip-card" style="padding:0; margin-bottom:16px;">
    <summary style="cursor:pointer; padding:14px var(--rip-space-xl); font-weight:600; color:var(--rip-gray-700);">
        Understanding Threat Intel &mdash; what these two lists mean
    </summary>
    <div style="padding:0 var(--rip-space-xl) var(--rip-space-xl); font-size:var(--rip-font-size-base); color:var(--rip-gray-600); line-height:1.65;">
        <p style="margin-bottom:12px;">
            While <strong>Logs</strong> records every suspicious request, this page shows what attackers left behind
            once they engaged with the high-interaction traps.
        </p>
        <p style="margin-bottom:12px;">
            <strong>Honeytokens</strong> are unique fake credentials the honeypot leaks when an attacker grabs a fake
            config file (<code>.env</code>, <code>.git/config</code>, phpMyAdmin). Each value is tied to the source IP
            and stored here as <em>Armed</em>. If that value is ever replayed against the honeypot &mdash; from any IP
            &mdash; it flips to <em>Triggered</em>: a confirmed-malicious signal with near-zero false positives, because
            the credential only ever existed inside a hidden honeypot response. The list pairs the IP the token was
            <em>leaked to</em> with the IP that <em>reused</em> it.
        </p>
        <p style="margin-bottom:12px;">
            <strong>Captured Payloads</strong> are the raw data attackers submitted to the traps: uploaded plugin/theme
            archives from the sticky fake admin, commands and passwords POSTed to the webshell trap, and logins sent to
            the fake phpMyAdmin/Adminer panels. Open one with <em>View</em>, or grab the original bytes with
            <em>Download raw</em>.
        </p>
        <p style="margin:0; color:var(--rip-gray-500);">
            <strong>Safety:</strong> captured payloads are attacker-controlled and may be hostile (real webshells,
            malware archives). They are shown only as escaped, inert text with control bytes neutralised &mdash; never
            executed or rendered as active markup. The raw download is served as a plain attachment.
        </p>
    </div>
</details>

<!-- Summary Cards -->
<div style="display:grid; grid-template-columns: repeat(4, 1fr); gap:12px; margin-bottom:24px;">
    <div class="rip-stat-card" style="flex-direction:column; text-align:center; gap:4px;">
        <div class="rip-stat-card__label">Honeytokens Issued</div>
        <div class="rip-stat-card__value" style="font-size:var(--rip-font-size-2xl); color:var(--rip-primary);"><?= number_format($summary['tokens_issued']) ?></div>
    </div>
    <div class="rip-stat-card" style="flex-direction:column; text-align:center; gap:4px;">
        <div class="rip-stat-card__label">Honeytokens Triggered</div>
        <div class="rip-stat-card__value" style="font-size:var(--rip-font-size-2xl); color:var(--rip-danger);"><?= number_format($summary['tokens_triggered']) ?></div>
    </div>
    <div class="rip-stat-card" style="flex-direction:column; text-align:center; gap:4px;">
        <div class="rip-stat-card__label">Payloads Captured</div>
        <div class="rip-stat-card__value" style="font-size:var(--rip-font-size-2xl); color:var(--rip-warning);"><?= number_format($summary['captures']) ?></div>
    </div>
    <div class="rip-stat-card" style="flex-direction:column; text-align:center; gap:4px;">
        <div class="rip-stat-card__label">Captured Volume</div>
        <div class="rip-stat-card__value" style="font-size:var(--rip-font-size-2xl); color:var(--rip-gray-700);"><?= $fmtSize((int) $summary['capture_bytes']) ?></div>
    </div>
</div>

<!-- Tabs -->
<div class="rip-nav-tabs">
    <a href="<?= $base ?>/intel?tab=tokens" class="rip-nav-tabs__tab <?= $tab === 'tokens' ? 'rip-nav-tabs__tab--active' : '' ?>">Honeytokens</a>
    <a href="<?= $base ?>/intel?tab=captures" class="rip-nav-tabs__tab <?= $tab === 'captures' ? 'rip-nav-tabs__tab--active' : '' ?>">Captured Payloads</a>
</div>

<?php if ($tab === 'tokens'): ?>
<!-- Honeytokens -->
<div class="rip-card">
    <div class="rip-card__header">
        Issued Canary Credentials
        <span style="float:right; font-size:var(--rip-font-size-sm); font-weight:400; color:var(--rip-gray-500);"><?= number_format($tokens['total']) ?> tokens</span>
    </div>
    <div style="overflow-x:auto;">
        <table class="rip-table">
            <thead>
                <tr>
                    <th>Status</th>
                    <th>Type</th>
                    <th>Token</th>
                    <th>Leaked via</th>
                    <th>Issued to IP</th>
                    <th>Triggered by IP</th>
                    <th>Triggered at</th>
                    <th>Hits</th>
                </tr>
            </thead>
            <tbody>
            <?php if (!empty($tokens['rows'])): ?>
                <?php foreach ($tokens['rows'] as $t): ?>
                    <?php $isTriggered = (int) ($t['triggered'] ?? 0) === 1; ?>
                    <tr>
                        <td>
                            <?php if ($isTriggered): ?>
                                <span class="rip-badge rip-badge--severity-critical">Triggered</span>
                            <?php else: ?>
                                <span class="rip-badge rip-badge--severity-low">Armed</span>
                            <?php endif; ?>
                        </td>
                        <td><?= htmlspecialchars(str_replace('_', ' ', (string) $t['token_type']), ENT_QUOTES, 'UTF-8') ?></td>
                        <td style="font-family:var(--rip-font-mono); font-size:var(--rip-font-size-sm);"><?= htmlspecialchars((string) $t['token'], ENT_QUOTES, 'UTF-8') ?></td>
                        <td style="max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:var(--rip-font-size-sm);" title="<?= htmlspecialchars((string) $t['source_path'], ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars((string) $t['source_path'], ENT_QUOTES, 'UTF-8') ?></td>
                        <td style="font-family:var(--rip-font-mono); white-space:nowrap;"><?= htmlspecialchars((string) $t['issued_to_ip'], ENT_QUOTES, 'UTF-8') ?></td>
                        <td style="font-family:var(--rip-font-mono); white-space:nowrap;"><?= htmlspecialchars((string) ($t['triggered_by_ip'] ?? '—'), ENT_QUOTES, 'UTF-8') ?></td>
                        <td style="white-space:nowrap; font-size:var(--rip-font-size-sm); color:var(--rip-gray-500);"><?= htmlspecialchars((string) ($t['triggered_at'] ?? '—'), ENT_QUOTES, 'UTF-8') ?></td>
                        <td><?= number_format((int) ($t['trigger_count'] ?? 0)) ?></td>
                    </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr><td colspan="8" class="rip-empty-state__text" style="text-align:center; padding:20px;">No honeytokens issued yet. They are minted when an attacker grabs a fake config file (.env, .git, phpMyAdmin).</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>
<?php $pg = $tokens; $pgTab = 'tokens'; ?>
<?php else: ?>
<!-- Captured Payloads -->
<div class="rip-card">
    <div class="rip-card__header">
        Captured Payloads
        <span style="float:right; font-size:var(--rip-font-size-sm); font-weight:400; color:var(--rip-gray-500);"><?= number_format($captures['total']) ?> payloads</span>
    </div>
    <div style="overflow-x:auto;">
        <table class="rip-table">
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>IP</th>
                    <th>Source</th>
                    <th>Filename</th>
                    <th>Size</th>
                    <th>URI</th>
                    <th></th>
                </tr>
            </thead>
            <tbody>
            <?php if (!empty($captures['rows'])): ?>
                <?php foreach ($captures['rows'] as $c): ?>
                    <tr>
                        <td style="white-space:nowrap; font-size:var(--rip-font-size-sm); color:var(--rip-gray-500);"><?= htmlspecialchars((string) $c['timestamp'], ENT_QUOTES, 'UTF-8') ?></td>
                        <td style="font-family:var(--rip-font-mono); white-space:nowrap;"><?= htmlspecialchars((string) $c['ip'], ENT_QUOTES, 'UTF-8') ?></td>
                        <td><span class="rip-badge rip-badge--cat"><?= htmlspecialchars(str_replace('_', ' ', (string) $c['capture_type']), ENT_QUOTES, 'UTF-8') ?></span></td>
                        <td style="font-size:var(--rip-font-size-sm);"><?= htmlspecialchars((string) ($c['filename'] ?? ''), ENT_QUOTES, 'UTF-8') ?: '<span style="color:var(--rip-gray-400)">—</span>' ?></td>
                        <td style="white-space:nowrap;"><?= $fmtSize((int) $c['size']) ?></td>
                        <td style="max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:var(--rip-font-size-sm);" title="<?= htmlspecialchars((string) $c['request_uri'], ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars((string) $c['request_uri'], ENT_QUOTES, 'UTF-8') ?></td>
                        <td><a href="<?= $base ?>/intel/capture/<?= (int) $c['id'] ?>" class="rip-link">View</a></td>
                    </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr><td colspan="7" class="rip-empty-state__text" style="text-align:center; padding:20px;">No payloads captured yet. Fake-admin uploads, webshell POSTs and DB-admin logins land here.</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>
<?php $pg = $captures; $pgTab = 'captures'; ?>
<?php endif; ?>

<?php if (($pg['pages'] ?? 1) > 1): ?>
<div class="rip-pagination">
    <?php $q = $base . '/intel?tab=' . $pgTab . '&'; ?>
    <?php if ($pg['page'] > 1): ?>
        <a href="<?= htmlspecialchars($q . 'page=' . ($pg['page'] - 1), ENT_QUOTES, 'UTF-8') ?>">&laquo;</a>
    <?php endif; ?>
    <?php for ($i = max(1, $pg['page'] - 3); $i <= min($pg['pages'], $pg['page'] + 3); $i++): ?>
        <?php if ($i === $pg['page']): ?>
            <span class="current"><?= $i ?></span>
        <?php else: ?>
            <a href="<?= htmlspecialchars($q . 'page=' . $i, ENT_QUOTES, 'UTF-8') ?>"><?= $i ?></a>
        <?php endif; ?>
    <?php endfor; ?>
    <?php if ($pg['page'] < $pg['pages']): ?>
        <a href="<?= htmlspecialchars($q . 'page=' . ($pg['page'] + 1), ENT_QUOTES, 'UTF-8') ?>">&raquo;</a>
    <?php endif; ?>
</div>
<?php endif; ?>

<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
?>
