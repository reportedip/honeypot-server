<?php
/**
 * Admin Log Detail Template
 *
 * Variables: $entry, $admin_path, $categoryRegistry (class name for static calls)
 */

$page_title = 'Log Entry #' . (int)$entry['id'];
$active_tab = 'logs';

ob_start();
?>

<div style="margin-bottom:16px;">
    <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/logs" class="rip-link" style="font-size:var(--rip-font-size-base);">&larr; Back to Logs</a>
</div>

<div class="rip-card">
    <div class="rip-card__header">Log Entry #<?= (int)$entry['id'] ?></div>
    <table class="rip-table">
        <tbody>
            <tr>
                <th style="width:140px;">IP Address</th>
                <td style="font-family:var(--rip-font-mono);">
                    <?= htmlspecialchars($entry['ip'], ENT_QUOTES, 'UTF-8') ?>
                    <a href="https://reportedip.de/ip/<?= urlencode($entry['ip']) ?>/" target="_blank" rel="noopener" class="rip-ip-external" title="View on reportedip.de">&#8599;</a>
                </td>
            </tr>
            <tr>
                <th>Categories</th>
                <td><?= $categoryRegistry::formatBadges($entry['categories'] ?? '') ?></td>
            </tr>
            <tr><th>Comment</th><td><?= htmlspecialchars($entry['comment'] ?? '', ENT_QUOTES, 'UTF-8') ?></td></tr>
            <tr><th>Request URI</th><td style="font-family:var(--rip-font-mono); word-break:break-all;"><?= htmlspecialchars($entry['request_uri'] ?? '', ENT_QUOTES, 'UTF-8') ?></td></tr>
            <tr><th>Method</th><td><span class="rip-badge rip-badge--method"><?= htmlspecialchars($entry['request_method'] ?? 'GET', ENT_QUOTES, 'UTF-8') ?></span></td></tr>
            <tr><th>User-Agent</th><td style="word-break:break-all; font-size:var(--rip-font-size-sm);"><?= htmlspecialchars($entry['user_agent'] ?? '', ENT_QUOTES, 'UTF-8') ?></td></tr>
            <tr><th>Timestamp</th><td><?= htmlspecialchars($entry['timestamp'] ?? '', ENT_QUOTES, 'UTF-8') ?></td></tr>
            <tr>
                <th>Status</th>
                <td>
                    <?php $sent = (int)($entry['sent'] ?? 0); ?>
                    <?php if ($sent === 1): ?>
                        <span class="rip-badge rip-badge--sent">Sent to API</span>
                    <?php elseif ($sent === 2): ?>
                        <span class="rip-badge rip-badge--whitelisted">Whitelisted (skipped)</span>
                    <?php else: ?>
                        <span class="rip-badge rip-badge--pending">Pending</span>
                    <?php endif; ?>
                </td>
            </tr>
            <?php if (!empty($entry['post_data'])): ?>
            <tr>
                <th>POST Data</th>
                <td>
                    <pre style="background:var(--rip-bg-code); padding:12px; border-radius:var(--rip-radius-md); font-size:var(--rip-font-size-sm); overflow-x:auto; max-height:300px; margin:0;"><?php
                        $decoded = json_decode($entry['post_data'], true);
                        if ($decoded !== null) {
                            echo htmlspecialchars(json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), ENT_QUOTES, 'UTF-8');
                        } else {
                            echo htmlspecialchars($entry['post_data'], ENT_QUOTES, 'UTF-8');
                        }
                    ?></pre>
                </td>
            </tr>
            <?php endif; ?>
        </tbody>
    </table>
</div>

<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
?>
