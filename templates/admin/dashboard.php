<?php
/**
 * Admin Dashboard Template
 *
 * Variables: $stats, $recent_logs, $whitelist, $system, $chart_data,
 *            $admin_path, $csrf_token, $message, $message_type, $active_tab,
 *            $categoryRegistry (class name for static calls)
 */

$page_title = 'Dashboard';
$active_tab = $active_tab ?? 'dashboard';

ob_start();
?>

<?php if (!($system['api_configured'] ?? false)): ?>
<div class="rip-alert" style="background:var(--rip-warning-light); color:var(--rip-warning-text); border:1px solid var(--rip-warning-border); padding:14px 18px; margin-bottom:20px; border-radius:var(--rip-radius-lg); font-size:var(--rip-font-size-base); line-height:1.6;">
    <strong>No Community Access Key configured.</strong> Without an API key, detected attacks are logged locally but not reported to the <a href="https://reportedip.de" target="_blank" rel="noopener" style="color:var(--rip-warning-text); text-decoration:underline;">reportedip.de</a> community database.<br>
    To get your free API key, please contact <a href="mailto:1@reportedip.de" style="color:var(--rip-warning-text); font-weight:700; text-decoration:underline;">1@reportedip.de</a> &mdash; we're looking for testers and community members to help improve detection coverage.
</div>
<?php endif; ?>

<!-- Stats Cards -->
<div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:14px; margin-bottom:24px;">
    <div class="rip-stat-card">
        <div class="rip-stat-card__icon rip-stat-card__icon--danger">
            <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 5a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 5zm0 9a1 1 0 100-2 1 1 0 000 2z" clip-rule="evenodd"/></svg>
        </div>
        <div class="rip-stat-card__content">
            <div class="rip-stat-card__label">Total Attacks</div>
            <div class="rip-stat-card__value" style="color:var(--rip-gray-900);"><?= number_format($stats['total'] ?? 0) ?></div>
        </div>
    </div>
    <div class="rip-stat-card">
        <div class="rip-stat-card__icon rip-stat-card__icon--warning">
            <svg viewBox="0 0 20 20" fill="currentColor"><path d="M10 2a8 8 0 100 16 8 8 0 000-16zm.75 4.75a.75.75 0 00-1.5 0v3.5a.75.75 0 00.37.65l2.5 1.5a.75.75 0 10.76-1.3L10.75 9.5V6.75z"/></svg>
        </div>
        <div class="rip-stat-card__content">
            <div class="rip-stat-card__label">Today</div>
            <div class="rip-stat-card__value" style="color:var(--rip-warning);"><?= number_format($stats['today'] ?? 0) ?></div>
        </div>
    </div>
    <div class="rip-stat-card">
        <div class="rip-stat-card__icon rip-stat-card__icon--info">
            <svg viewBox="0 0 20 20" fill="currentColor"><path d="M10 8a3 3 0 100-6 3 3 0 000 6zM3.465 14.493a1.23 1.23 0 00.41 1.412A9.957 9.957 0 0010 18c2.31 0 4.438-.784 6.131-2.1.43-.333.604-.903.408-1.41a7.002 7.002 0 00-13.074.003z"/></svg>
        </div>
        <div class="rip-stat-card__content">
            <div class="rip-stat-card__label">Unique IPs</div>
            <div class="rip-stat-card__value" style="color:var(--rip-info);"><?= number_format($stats['unique_ips'] ?? 0) ?></div>
        </div>
    </div>
    <div class="rip-stat-card">
        <div class="rip-stat-card__icon rip-stat-card__icon--success">
            <svg viewBox="0 0 20 20" fill="currentColor"><path d="M3.196 12.87l-.825.483a.75.75 0 000 1.294l7.25 4.25a.75.75 0 00.758 0l7.25-4.25a.75.75 0 000-1.294l-.825-.484-5.666 3.322a2.25 2.25 0 01-2.276 0L3.196 12.87zM10 2.25L2.371 6.727a.75.75 0 000 1.294l7.25 4.25a.75.75 0 00.758 0l7.25-4.25a.75.75 0 000-1.294L10 2.25z"/></svg>
        </div>
        <div class="rip-stat-card__content">
            <div class="rip-stat-card__label">Queue Size</div>
            <div class="rip-stat-card__value" style="color:<?= ($stats['pending'] ?? 0) > 100 ? 'var(--rip-danger)' : 'var(--rip-success)' ?>;"><?= number_format($stats['pending'] ?? 0) ?></div>
        </div>
    </div>
</div>

<!-- Activity Chart (last 24h) -->
<div class="rip-card">
    <div class="rip-card__header">Activity (Last 24 Hours)</div>
    <?php
    $maxCount = 1;
    foreach ($chart_data as $bar) {
        if ($bar['count'] > $maxCount) {
            $maxCount = $bar['count'];
        }
    }
    ?>
    <div style="display:flex; align-items:flex-end; gap:3px; height:120px; padding-top:8px;">
        <?php foreach ($chart_data as $bar): ?>
            <?php $pct = $maxCount > 0 ? ($bar['count'] / $maxCount) * 100 : 0; ?>
            <div style="flex:1; display:flex; flex-direction:column; align-items:center; justify-content:flex-end; height:100%;" title="<?= htmlspecialchars($bar['hour'], ENT_QUOTES, 'UTF-8') ?>: <?= $bar['count'] ?> events">
                <div style="width:100%; min-height:2px; max-height:100%; height:<?= max(2, $pct) ?>%; background:<?= $pct > 70 ? 'var(--rip-danger)' : ($pct > 30 ? 'var(--rip-warning)' : 'var(--rip-primary)') ?>; border-radius:3px 3px 0 0; transition:height 0.3s;"></div>
            </div>
        <?php endforeach; ?>
    </div>
    <div style="display:flex; gap:3px; margin-top:4px;">
        <?php foreach ($chart_data as $i => $bar): ?>
            <?php if ($i % 4 === 0): ?>
                <div style="flex:1; text-align:center; font-size:var(--rip-font-size-xs); color:var(--rip-gray-400);"><?= htmlspecialchars($bar['hour'], ENT_QUOTES, 'UTF-8') ?></div>
            <?php else: ?>
                <div style="flex:1;"></div>
            <?php endif; ?>
        <?php endforeach; ?>
    </div>
</div>

<!-- Visitor Breakdown (24h) -->
<?php
    $vStats = $visitor_stats ?? ['counts' => [], 'top_bots' => []];
    $vCounts = $vStats['counts'] ?? [];
    $vTopBots = $vStats['top_bots'] ?? [];
    $vTotal = array_sum($vCounts);
    $vTypeLabels = [
        'good_bot' => ['label' => 'Good Bots', 'color' => 'var(--rip-success)', 'raw' => '#10b981'],
        'ai_agent' => ['label' => 'AI Agents', 'color' => '#8b5cf6', 'raw' => '#8b5cf6'],
        'bad_bot'  => ['label' => 'Bad Bots', 'color' => 'var(--rip-danger)', 'raw' => '#ef4444'],
        'hacker'   => ['label' => 'Hackers', 'color' => 'var(--rip-warning)', 'raw' => '#f59e0b'],
        'human'    => ['label' => 'Humans', 'color' => 'var(--rip-primary)', 'raw' => '#6366f1'],
    ];
?>
<div style="display:grid; grid-template-columns: 1fr 1fr; gap:20px; margin-bottom:20px;">
    <div class="rip-card" style="margin-bottom:0;">
        <div class="rip-card__header">Visitor Breakdown (24h)
            <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/visitors" class="rip-link" style="float:right; font-size:var(--rip-font-size-sm); font-weight:400;">View All &rarr;</a>
        </div>
        <?php if ($vTotal > 0): ?>
        <?php foreach ($vTypeLabels as $vType => $vInfo): ?>
            <?php $vCount = $vCounts[$vType] ?? 0; $vPct = $vTotal > 0 ? ($vCount / $vTotal) * 100 : 0; ?>
            <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px; font-size:var(--rip-font-size-base);">
                <span style="width:90px; color:var(--rip-gray-500);"><?= htmlspecialchars($vInfo['label'], ENT_QUOTES, 'UTF-8') ?></span>
                <div style="flex:1; height:18px; background:var(--rip-bg); border-radius:var(--rip-radius-sm); overflow:hidden;">
                    <div style="width:<?= max(0, $vPct) ?>%; height:100%; background:<?= htmlspecialchars($vInfo['raw'], ENT_QUOTES, 'UTF-8') ?>; border-radius:var(--rip-radius-sm);"></div>
                </div>
                <span style="min-width:50px; text-align:right; font-weight:600;"><?= number_format($vCount) ?></span>
            </div>
        <?php endforeach; ?>
        <?php else: ?>
        <div class="rip-empty-state">
            <div class="rip-empty-state__text">No visitor data yet.</div>
        </div>
        <?php endif; ?>
    </div>

    <div class="rip-card" style="margin-bottom:0;">
        <div class="rip-card__header">Top Bots & Agents (24h)</div>
        <table class="rip-table">
            <thead><tr><th>Bot Name</th><th>Type</th><th style="text-align:right;">Requests</th></tr></thead>
            <tbody>
            <?php if (!empty($vTopBots)): ?>
                <?php foreach (array_slice($vTopBots, 0, 8) as $bot): ?>
                    <?php $bInfo = $vTypeLabels[$bot['visitor_type']] ?? ['label' => $bot['visitor_type'], 'raw' => '#888']; ?>
                    <tr>
                        <td><?= htmlspecialchars($bot['bot_name'] ?? '', ENT_QUOTES, 'UTF-8') ?></td>
                        <td><span class="rip-badge" style="background:<?= htmlspecialchars($bInfo['raw'], ENT_QUOTES, 'UTF-8') ?>22; color:<?= htmlspecialchars($bInfo['raw'], ENT_QUOTES, 'UTF-8') ?>;"><?= htmlspecialchars($bInfo['label'], ENT_QUOTES, 'UTF-8') ?></span></td>
                        <td style="text-align:right; font-weight:600;"><?= number_format((int)($bot['cnt'] ?? 0)) ?></td>
                    </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr><td colspan="3" class="rip-empty-state__text" style="text-align:center; padding:20px;">No data yet.</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<div style="display:grid; grid-template-columns: 1fr 1fr; gap:20px;">
    <!-- Top Attacking IPs -->
    <div class="rip-card">
        <div class="rip-card__header">Top 10 Attacking IPs</div>
        <table class="rip-table">
            <thead><tr><th>IP Address</th><th style="text-align:right;">Events</th></tr></thead>
            <tbody>
            <?php if (!empty($stats['top_ips'])): ?>
                <?php foreach ($stats['top_ips'] as $row): ?>
                    <tr>
                        <td>
                            <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/logs?ip=<?= urlencode($row['ip']) ?>" class="rip-link">
                                <?= htmlspecialchars($row['ip'], ENT_QUOTES, 'UTF-8') ?>
                            </a>
                            <a href="https://reportedip.de/ip/<?= urlencode($row['ip']) ?>/" target="_blank" rel="noopener" class="rip-ip-external" title="View on reportedip.de">&#8599;</a>
                        </td>
                        <td style="text-align:right; font-weight:600;"><?= number_format((int)$row['cnt']) ?></td>
                    </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr><td colspan="2" class="rip-empty-state__text" style="text-align:center; padding:20px;">No data yet.</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>

    <!-- Top Categories -->
    <div class="rip-card">
        <div class="rip-card__header">Top 10 Categories</div>
        <table class="rip-table">
            <thead><tr><th>Categories</th><th style="text-align:right;">Events</th></tr></thead>
            <tbody>
            <?php if (!empty($stats['top_categories'])): ?>
                <?php foreach ($stats['top_categories'] as $row): ?>
                    <tr>
                        <td><?= $categoryRegistry::formatBadges($row['categories']) ?></td>
                        <td style="text-align:right; font-weight:600;"><?= number_format((int)$row['cnt']) ?></td>
                    </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr><td colspan="2" class="rip-empty-state__text" style="text-align:center; padding:20px;">No data yet.</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<!-- Whitelist Section -->
<?php if (($active_tab ?? '') === 'whitelist'): ?>
<div class="rip-card" id="whitelist-section">
    <div class="rip-card__header">IP Whitelist</div>
    <form method="post" action="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/whitelist" style="display:flex; gap:8px; margin-bottom:16px; flex-wrap:wrap;">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token ?? '', ENT_QUOTES, 'UTF-8') ?>">
        <input type="hidden" name="action" value="add">
        <input type="text" name="ip" placeholder="IP or CIDR (e.g. 192.168.1.0/24)" required class="rip-input" style="flex:1; min-width:180px;">
        <input type="text" name="description" placeholder="Description (optional)" class="rip-input" style="flex:1; min-width:140px;">
        <button type="submit" class="rip-button rip-button--primary">Add</button>
    </form>
    <table class="rip-table">
        <thead><tr><th>IP Address</th><th>Description</th><th>Added</th><th>Active</th><th>Action</th></tr></thead>
        <tbody>
        <?php if (!empty($whitelist)): ?>
            <?php foreach ($whitelist as $entry): ?>
                <tr>
                    <td style="font-family:var(--rip-font-mono);"><?= htmlspecialchars($entry['ip_address'], ENT_QUOTES, 'UTF-8') ?></td>
                    <td><?= htmlspecialchars($entry['description'] ?? '', ENT_QUOTES, 'UTF-8') ?></td>
                    <td style="white-space:nowrap;"><?= htmlspecialchars($entry['added_date'] ?? '', ENT_QUOTES, 'UTF-8') ?></td>
                    <td><span class="rip-badge <?= $entry['is_active'] ? 'rip-badge--sent' : 'rip-badge--pending' ?>"><?= $entry['is_active'] ? 'Yes' : 'No' ?></span></td>
                    <td>
                        <?php if ($entry['is_active']): ?>
                        <form method="post" action="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/whitelist" style="display:inline;">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token ?? '', ENT_QUOTES, 'UTF-8') ?>">
                            <input type="hidden" name="action" value="remove">
                            <input type="hidden" name="ip" value="<?= htmlspecialchars($entry['ip_address'], ENT_QUOTES, 'UTF-8') ?>">
                            <button type="submit" class="rip-button rip-button--danger">Remove</button>
                        </form>
                        <?php endif; ?>
                    </td>
                </tr>
            <?php endforeach; ?>
        <?php else: ?>
            <tr><td colspan="5" class="rip-empty-state__text" style="text-align:center; padding:20px;">Whitelist is empty.</td></tr>
        <?php endif; ?>
        </tbody>
    </table>
</div>
<?php endif; ?>

<!-- Recent Attacks -->
<div class="rip-card">
    <div class="rip-card__header">Recent Attacks (Last 20)
        <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/logs" class="rip-link" style="float:right; font-size:var(--rip-font-size-sm); font-weight:400;">View All &rarr;</a>
    </div>
    <div style="overflow-x:auto;">
        <table class="rip-table">
            <thead><tr><th>IP</th><th>Categories</th><th>URI</th><th>Method</th><th>Timestamp</th><th>Status</th></tr></thead>
            <tbody>
            <?php if (!empty($recent_logs)): ?>
                <?php foreach (array_slice($recent_logs, 0, 20) as $log): ?>
                    <tr>
                        <td style="font-family:var(--rip-font-mono); white-space:nowrap;">
                            <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/logs?ip=<?= urlencode($log['ip']) ?>" class="rip-link"><?= htmlspecialchars($log['ip'], ENT_QUOTES, 'UTF-8') ?></a>
                            <a href="https://reportedip.de/ip/<?= urlencode($log['ip']) ?>/" target="_blank" rel="noopener" class="rip-ip-external" title="View on reportedip.de">&#8599;</a>
                        </td>
                        <td><?= $categoryRegistry::formatBadges($log['categories'] ?? '') ?></td>
                        <td style="max-width:250px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="<?= htmlspecialchars($log['request_uri'] ?? '', ENT_QUOTES, 'UTF-8') ?>">
                            <?= htmlspecialchars($log['request_uri'] ?? '', ENT_QUOTES, 'UTF-8') ?>
                        </td>
                        <td><span class="rip-badge rip-badge--method"><?= htmlspecialchars($log['request_method'] ?? 'GET', ENT_QUOTES, 'UTF-8') ?></span></td>
                        <td style="white-space:nowrap; font-size:var(--rip-font-size-sm); color:var(--rip-gray-500);"><?= htmlspecialchars($log['timestamp'] ?? '', ENT_QUOTES, 'UTF-8') ?></td>
                        <td>
                            <?php $sent = (int)($log['sent'] ?? 0); ?>
                            <?php if ($sent === 1): ?>
                                <span class="rip-badge rip-badge--sent">Sent</span>
                            <?php elseif ($sent === 2): ?>
                                <span class="rip-badge rip-badge--whitelisted">Whitelisted</span>
                            <?php else: ?>
                                <span class="rip-badge rip-badge--pending">Pending</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr><td colspan="6" class="rip-empty-state__text" style="text-align:center; padding:20px;">No attacks recorded yet.</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<!-- Queue Processing Status -->
<?php
    $queueMode = $system['queue_mode'] ?? 'web';
    $cron = $cron_status ?? [];
    $cronHealth = $cron['health'] ?? 'unknown';
    $cronColors = [
        'healthy'  => ['bg' => 'var(--rip-success-light)', 'color' => 'var(--rip-success-text)', 'border' => 'var(--rip-success-border)', 'dot' => 'var(--rip-success)'],
        'warning'  => ['bg' => 'var(--rip-warning-light)', 'color' => 'var(--rip-warning-text)', 'border' => 'var(--rip-warning-border)', 'dot' => 'var(--rip-warning)'],
        'critical' => ['bg' => 'var(--rip-danger-light)', 'color' => 'var(--rip-danger-text)', 'border' => 'var(--rip-danger-border)', 'dot' => 'var(--rip-danger)'],
        'unknown'  => ['bg' => 'var(--rip-gray-100)', 'color' => 'var(--rip-gray-500)', 'border' => 'var(--rip-gray-300)', 'dot' => 'var(--rip-gray-400)'],
    ];
    $cc = $cronColors[$cronHealth] ?? $cronColors['unknown'];
?>
<div class="rip-card">
    <div class="rip-card__header">
        Queue Processing
        <span class="rip-badge" style="margin-left:8px; background:<?= $queueMode === 'web' ? 'var(--rip-primary)' : 'var(--rip-gray-500)' ?>; color:#fff; font-size:var(--rip-font-size-xs); font-weight:500; padding:2px 8px; border-radius:var(--rip-radius-full);"><?= $queueMode === 'web' ? 'Web Mode' : 'Cron Mode' ?></span>
        <span style="float:right; display:inline-flex; align-items:center; gap:6px; font-size:var(--rip-font-size-sm); font-weight:400; background:<?= $cc['bg'] ?>; color:<?= $cc['color'] ?>; border:1px solid <?= $cc['border'] ?>; padding:2px 10px; border-radius:var(--rip-radius-full);">
            <span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:<?= $cc['dot'] ?>;"></span>
            <?= ucfirst($cronHealth) ?>
        </span>
    </div>

    <?php if ($cron['configured'] ?? false): ?>
        <!-- Cron is running -->
        <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap:12px; font-size:var(--rip-font-size-base); margin-bottom:16px;">
            <div>
                <span style="color:var(--rip-gray-500);">Last Run:</span><br>
                <strong><?= htmlspecialchars($cron['last_run'] ?? 'Never', ENT_QUOTES, 'UTF-8') ?></strong>
                <?php if (($cron['age_minutes'] ?? null) !== null): ?>
                    <span style="color:var(--rip-gray-500); font-size:var(--rip-font-size-xs);">(<?= $cron['age_minutes'] ?> min ago)</span>
                <?php endif; ?>
            </div>
            <div>
                <span style="color:var(--rip-gray-500);">Total Runs:</span><br>
                <strong><?= number_format($cron['runs_count'] ?? 0) ?></strong>
            </div>
            <div>
                <span style="color:var(--rip-gray-500);">Reports Sent:</span><br>
                <strong style="color:var(--rip-success);"><?= number_format($cron['total_sent'] ?? 0) ?></strong>
            </div>
            <div>
                <span style="color:var(--rip-gray-500);">Reports Failed:</span><br>
                <strong style="color:<?= ($cron['total_failed'] ?? 0) > 0 ? 'var(--rip-danger)' : 'var(--rip-gray-500)' ?>;"><?= number_format($cron['total_failed'] ?? 0) ?></strong>
            </div>
        </div>

        <?php if (!empty($cron['last_result'])): ?>
        <div style="font-size:var(--rip-font-size-sm); color:var(--rip-gray-500); margin-bottom:12px; padding:8px 12px; background:var(--rip-gray-50); border-radius:var(--rip-radius-md);">
            Last batch: <strong><?= (int)$cron['last_result']['sent'] ?></strong> sent,
            <strong><?= (int)$cron['last_result']['failed'] ?></strong> failed,
            <strong><?= (int)$cron['last_result']['skipped'] ?></strong> skipped<?php if (($cron['last_result']['cleaned'] ?? 0) > 0): ?>,
            <strong><?= number_format((int)$cron['last_result']['cleaned']) ?></strong> cleaned up<?php endif; ?>
            <?php if (($cron['last_result']['remaining'] ?? 0) > 0): ?>
                &mdash; <strong><?= number_format((int)$cron['last_result']['remaining']) ?></strong> still pending
            <?php endif; ?>
            <?php if ($cron['last_result']['had_errors'] ?? false): ?>
                &mdash; <span style="color:var(--rip-danger);">had errors (see api_errors.log)</span>
            <?php endif; ?>
        </div>
        <?php endif; ?>

        <?php if (!empty($cron['history'])): ?>
        <div style="font-size:var(--rip-font-size-xs); color:var(--rip-gray-500); margin-bottom:12px;">
            <strong style="color:var(--rip-gray-600);">Last <?= count($cron['history']) ?> runs:</strong>
            <div style="display:flex; gap:2px; margin-top:6px; height:40px; align-items:flex-end;">
                <?php
                    $maxSent = 1;
                    foreach ($cron['history'] as $h) {
                        $val = ($h['sent'] ?? 0) + ($h['failed'] ?? 0);
                        if ($val > $maxSent) $maxSent = $val;
                    }
                ?>
                <?php foreach (array_reverse($cron['history']) as $h): ?>
                    <?php
                        $total = ($h['sent'] ?? 0) + ($h['failed'] ?? 0);
                        $pct = $maxSent > 0 ? ($total / $maxSent) * 100 : 0;
                        $color = ($h['failed'] ?? 0) > 0 ? 'var(--rip-danger)' : 'var(--rip-success)';
                        if ($total === 0) $color = 'var(--rip-gray-300)';
                    ?>
                    <div style="flex:1; min-height:3px; height:<?= max(3, $pct) ?>%; background:<?= $color ?>; border-radius:2px;" title="<?= htmlspecialchars($h['time'] ?? '', ENT_QUOTES, 'UTF-8') ?>: <?= $h['sent'] ?? 0 ?> sent, <?= $h['failed'] ?? 0 ?> failed"></div>
                <?php endforeach; ?>
            </div>
        </div>
        <?php endif; ?>

    <?php else: ?>
        <!-- Queue not yet active -->
        <div style="padding:12px 0; font-size:var(--rip-font-size-base); color:var(--rip-gray-500);">
            <?php if ($queueMode === 'web'): ?>
                Web cron mode is active. The queue is processed automatically during page visits.
            <?php else: ?>
                The cron job has not run yet. Set it up to automatically send pending reports to the reportedip.de API.
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <!-- Setup Instructions (collapsible) -->
    <details style="font-size:var(--rip-font-size-base); margin-top:8px; border-top:1px solid var(--rip-gray-100); padding-top:12px;">
        <summary style="cursor:pointer; color:var(--rip-primary); font-weight:600; font-size:var(--rip-font-size-sm); user-select:none;">
            <?php if ($queueMode === 'web'): ?>
                Queue Mode Info
            <?php else: ?>
                Cron Setup Instructions
            <?php endif; ?>
        </summary>
        <div style="margin-top:12px; display:flex; flex-direction:column; gap:14px;">

            <?php if ($queueMode === 'web'): ?>
            <div style="font-size:var(--rip-font-size-sm); padding:10px 14px; background:var(--rip-success-light); color:var(--rip-success-text); border:1px solid var(--rip-success-border); border-radius:var(--rip-radius-md);">
                <strong>Currently using web cron mode (automatic).</strong> The report queue is processed in small batches during each page visit. No external cron job is needed.<br>
                For high-traffic installations, switch to <code>'queue_mode' =&gt; 'cron'</code> in <code>config/config.php</code> and set up a cron job below.
            </div>
            <?php endif; ?>

            <div>
                <strong style="color:var(--rip-gray-600);">Linux / crontab</strong>
                <div style="font-size:var(--rip-font-size-xs); color:var(--rip-gray-500); margin:4px 0;">Recommended: every 5 minutes</div>
                <pre style="background:var(--rip-gray-900); color:var(--rip-gray-300); padding:10px 14px; border-radius:var(--rip-radius-md); font-size:var(--rip-font-size-sm); overflow-x:auto; margin:0;">*/5 * * * * cd <?= htmlspecialchars(dirname(__DIR__, 2), ENT_QUOTES, 'UTF-8') ?> && php cli.php process-queue >> data/cron.log 2>&1</pre>
                <div style="font-size:var(--rip-font-size-xs); color:var(--rip-success); margin-top:4px;">Cleanup of old entries runs automatically (retention: <?= (int)($system['retention_days'] ?? 90) ?> days).</div>
            </div>

            <div>
                <strong style="color:var(--rip-gray-600);">systemd Timer</strong>
                <div style="font-size:var(--rip-font-size-xs); color:var(--rip-gray-500); margin:4px 0;">Create <code>/etc/systemd/system/honeypot-queue.service</code> and <code>.timer</code></div>
                <pre style="background:var(--rip-gray-900); color:var(--rip-gray-300); padding:10px 14px; border-radius:var(--rip-radius-md); font-size:var(--rip-font-size-sm); overflow-x:auto; margin:0;"># honeypot-queue.service
[Unit]
Description=Honeypot Report Queue Processor

[Service]
Type=oneshot
WorkingDirectory=<?= htmlspecialchars(dirname(__DIR__, 2), ENT_QUOTES, 'UTF-8') ?>

ExecStart=/usr/bin/php cli.php process-queue
User=www-data</pre>
                <pre style="background:var(--rip-gray-900); color:var(--rip-gray-300); padding:10px 14px; border-radius:var(--rip-radius-md); font-size:var(--rip-font-size-sm); overflow-x:auto; margin:0 0 0 0; margin-top:6px;"># honeypot-queue.timer
[Unit]
Description=Run Honeypot Queue every 5 minutes

[Timer]
OnBootSec=60
OnUnitActiveSec=300

[Install]
WantedBy=timers.target</pre>
                <pre style="background:var(--rip-gray-900); color:var(--rip-gray-300); padding:10px 14px; border-radius:var(--rip-radius-md); font-size:var(--rip-font-size-sm); overflow-x:auto; margin:0; margin-top:6px;">sudo systemctl enable --now honeypot-queue.timer</pre>
            </div>

            <div>
                <strong style="color:var(--rip-gray-600);">Docker</strong>
                <div style="font-size:var(--rip-font-size-xs); color:var(--rip-gray-500); margin:4px 0;">Add to <code>docker-compose.yml</code> or use the built-in Docker cron:</div>
                <pre style="background:var(--rip-gray-900); color:var(--rip-gray-300); padding:10px 14px; border-radius:var(--rip-radius-md); font-size:var(--rip-font-size-sm); overflow-x:auto; margin:0;">docker exec honeypot-server php cli.php process-queue</pre>
            </div>

            <div>
                <strong style="color:var(--rip-gray-600);">Windows Task Scheduler</strong>
                <div style="font-size:var(--rip-font-size-xs); color:var(--rip-gray-500); margin:4px 0;">Create a scheduled task via PowerShell:</div>
                <pre style="background:var(--rip-gray-900); color:var(--rip-gray-300); padding:10px 14px; border-radius:var(--rip-radius-md); font-size:var(--rip-font-size-sm); overflow-x:auto; margin:0;">$action = New-ScheduledTaskAction -Execute "php" `
  -Argument "cli.php process-queue" `
  -WorkingDirectory "<?= htmlspecialchars(str_replace('/', '\\', dirname(__DIR__, 2)), ENT_QUOTES, 'UTF-8') ?>"
$trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) -Once -At (Get-Date)
Register-ScheduledTask -TaskName "HoneypotQueue" -Action $action -Trigger $trigger -RunLevel Highest</pre>
            </div>

            <div style="font-size:var(--rip-font-size-sm); padding:10px 14px; background:var(--rip-info-light); color:var(--rip-info-text); border:1px solid var(--rip-info-border); border-radius:var(--rip-radius-md);">
                <strong>CLI Commands:</strong><br>
                <code style="font-size:var(--rip-font-size-xs);">php cli.php process-queue</code> - Send pending reports + auto-cleanup<br>
                <code style="font-size:var(--rip-font-size-xs);">php cli.php cleanup --days=90</code> - Manual cleanup (standalone)<br>
                <code style="font-size:var(--rip-font-size-xs);">php cli.php stats</code> - Show statistics<br>
                <code style="font-size:var(--rip-font-size-xs);">php cli.php test-api</code> - Test API connection
            </div>
        </div>
    </details>
</div>

<!-- System Info -->
<div class="rip-card">
    <div class="rip-card__header">System Information</div>
    <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:12px; font-size:var(--rip-font-size-base);">
        <div><span style="color:var(--rip-gray-500);">Version:</span> <?= htmlspecialchars($system['app_version'] ?? '?', ENT_QUOTES, 'UTF-8') ?></div>
        <div><span style="color:var(--rip-gray-500);">PHP Version:</span> <?= htmlspecialchars($system['php_version'] ?? '', ENT_QUOTES, 'UTF-8') ?></div>
        <div><span style="color:var(--rip-gray-500);">CMS Profile:</span> <?= htmlspecialchars(ucfirst($system['cms_profile'] ?? ''), ENT_QUOTES, 'UTF-8') ?></div>
        <div><span style="color:var(--rip-gray-500);">API Configured:</span> <?= ($system['api_configured'] ?? false) ? '<span style="color:var(--rip-success);">Yes</span>' : '<span style="color:var(--rip-danger);">No</span>' ?></div>
        <div><span style="color:var(--rip-gray-500);">Database Size:</span> <?= htmlspecialchars($system['db_size'] ?? '0 B', ENT_QUOTES, 'UTF-8') ?></div>
        <div><span style="color:var(--rip-gray-500);">Debug Mode:</span> <?= ($system['debug_mode'] ?? false) ? '<span style="color:var(--rip-warning);">On</span>' : 'Off' ?></div>
        <div><span style="color:var(--rip-gray-500);">Log Retention:</span> <?= (int)($system['retention_days'] ?? 90) ?> days</div>
    </div>
</div>

<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
?>
