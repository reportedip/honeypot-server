<?php
/**
 * Admin Dashboard Template
 *
 * Variables: $stats, $recent_logs, $whitelist, $system, $chart_data, $chart_data_ranges,
 *            $cron_status, $recent_failures, $visitor_stats, $trends, $severity_breakdown,
 *            $top_uris, $intel, $webhook_summary,
 *            $admin_path, $csrf_token, $message, $message_type, $active_tab,
 *            $categoryRegistry (class name for static calls)
 */

$active_tab = $active_tab ?? 'dashboard';
$page_title = $active_tab === 'whitelist' ? 'Whitelist' : 'Dashboard';

$base = htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8');

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

/** Compact timestamp for feeds: "07-10 14:32". */
$fmtShortTs = static function (?string $ts): string {
    if ($ts === null || strlen($ts) < 16) {
        return (string) $ts;
    }
    return substr($ts, 5, 11);
};

ob_start();
?>

<?php if ($active_tab === 'dashboard'): ?>

<?php if (!($system['api_configured'] ?? false)): ?>
<div class="rip-alert rip-alert--warning">
    <strong>No Community Access Key configured.</strong> Without an API key, detected attacks are logged locally but not reported to the <a href="https://reportedip.com" target="_blank" rel="noopener" style="color:var(--rip-warning-text); text-decoration:underline;">reportedip.com</a> community database.<br>
    To get your free API key, please contact <a href="mailto:1@reportedip.com" style="color:var(--rip-warning-text); font-weight:700; text-decoration:underline;">1@reportedip.com</a> &mdash; we're looking for testers and community members to help improve detection coverage.
</div>
<?php endif; ?>

<?php if ((int) ($stats['total'] ?? 0) === 0): ?>
<div class="rip-alert rip-alert--info">
    <strong>Honeypot armed &mdash; no attacks recorded yet.</strong> The emulated <?= htmlspecialchars(ucfirst($system['cms_profile'] ?? 'CMS'), ENT_QUOTES, 'UTF-8') ?> installation is live. As soon as scanners and bots probe it, their activity will appear here.
</div>
<?php endif; ?>

<!-- KPI Cards -->
<?php
    $trend = $trends ?? ['today' => null, 'change_pct' => null, 'new_ips_today' => 0];
    $changePct = $trend['change_pct'];
    $intelSummary = $intel['summary'] ?? ['tokens_issued' => 0, 'tokens_triggered' => 0, 'captures' => 0, 'capture_bytes' => 0];
    $pendingCount = (int) ($stats['pending'] ?? 0);
?>
<div class="rip-grid rip-grid--kpi">
    <div class="rip-stat-card">
        <div class="rip-stat-card__icon rip-stat-card__icon--danger">
            <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 5a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 5zm0 9a1 1 0 100-2 1 1 0 000 2z" clip-rule="evenodd"/></svg>
        </div>
        <div class="rip-stat-card__content">
            <div class="rip-stat-card__label">Total Attacks</div>
            <div class="rip-stat-card__value" style="color:var(--rip-gray-900);" data-kpi="total"><?= number_format($stats['total'] ?? 0) ?></div>
        </div>
    </div>
    <div class="rip-stat-card">
        <div class="rip-stat-card__icon rip-stat-card__icon--warning">
            <svg viewBox="0 0 20 20" fill="currentColor"><path d="M10 2a8 8 0 100 16 8 8 0 000-16zm.75 4.75a.75.75 0 00-1.5 0v3.5a.75.75 0 00.37.65l2.5 1.5a.75.75 0 10.76-1.3L10.75 9.5V6.75z"/></svg>
        </div>
        <div class="rip-stat-card__content">
            <div class="rip-stat-card__label">Today</div>
            <div>
                <span class="rip-stat-card__value" style="color:var(--rip-warning);" data-kpi="today"><?= number_format($stats['today'] ?? 0) ?></span>
                <?php if ($changePct !== null): ?>
                    <?php $trendClass = $changePct > 0 ? 'up' : ($changePct < 0 ? 'down' : 'flat'); ?>
                    <span class="rip-stat-card__trend rip-stat-card__trend--<?= $trendClass ?>" title="Compared to yesterday (<?= number_format((int) ($trend['yesterday'] ?? 0)) ?> events)">
                        <?= $changePct > 0 ? '&#9650;' : ($changePct < 0 ? '&#9660;' : '&#8213;') ?> <?= abs($changePct) ?>%
                    </span>
                <?php endif; ?>
            </div>
            <div class="rip-stat-card__hint">vs. yesterday: <?= number_format((int) ($trend['yesterday'] ?? 0)) ?></div>
        </div>
    </div>
    <div class="rip-stat-card">
        <div class="rip-stat-card__icon rip-stat-card__icon--info">
            <svg viewBox="0 0 20 20" fill="currentColor"><path d="M10 8a3 3 0 100-6 3 3 0 000 6zM3.465 14.493a1.23 1.23 0 00.41 1.412A9.957 9.957 0 0010 18c2.31 0 4.438-.784 6.131-2.1.43-.333.604-.903.408-1.41a7.002 7.002 0 00-13.074.003z"/></svg>
        </div>
        <div class="rip-stat-card__content">
            <div class="rip-stat-card__label">Unique IPs</div>
            <div class="rip-stat-card__value" style="color:var(--rip-info);" data-kpi="unique_ips"><?= number_format($stats['unique_ips'] ?? 0) ?></div>
            <div class="rip-stat-card__hint"><?= number_format((int) ($trend['new_ips_today'] ?? 0)) ?> first seen today</div>
        </div>
    </div>
    <div class="rip-stat-card">
        <div class="rip-stat-card__icon rip-stat-card__icon--success">
            <svg viewBox="0 0 20 20" fill="currentColor"><path d="M3.196 12.87l-.825.483a.75.75 0 000 1.294l7.25 4.25a.75.75 0 00.758 0l7.25-4.25a.75.75 0 000-1.294l-.825-.484-5.666 3.322a2.25 2.25 0 01-2.276 0L3.196 12.87zM10 2.25L2.371 6.727a.75.75 0 000 1.294l7.25 4.25a.75.75 0 00.758 0l7.25-4.25a.75.75 0 000-1.294L10 2.25z"/></svg>
        </div>
        <div class="rip-stat-card__content">
            <div class="rip-stat-card__label">Report Queue</div>
            <div class="rip-stat-card__value" style="color:<?= $pendingCount > 100 ? 'var(--rip-danger)' : 'var(--rip-success)' ?>;" data-kpi="pending"><?= number_format($pendingCount) ?></div>
            <div class="rip-stat-card__hint"><?= ($system['queue_mode'] ?? 'web') === 'web' ? 'web mode (auto)' : 'cron mode' ?></div>
        </div>
    </div>
    <a class="rip-stat-card" href="<?= $base ?>/intel" title="Open Threat Intel">
        <div class="rip-stat-card__icon" style="background:var(--rip-gray-900); color:var(--rip-sidebar-active-text);">
            <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M3 2.75A.75.75 0 013.75 2h.5a.75.75 0 01.75.75V3h9.19c.83 0 1.3.94.8 1.6l-1.7 2.27a.25.25 0 000 .3l1.7 2.26c.5.66.03 1.6-.8 1.6H5v6.22a.75.75 0 01-.75.75h-.5a.75.75 0 01-.75-.75V2.75z" clip-rule="evenodd"/></svg>
        </div>
        <div class="rip-stat-card__content">
            <div class="rip-stat-card__label">Honeytokens Triggered</div>
            <div class="rip-stat-card__value" style="color:<?= ((int) $intelSummary['tokens_triggered']) > 0 ? 'var(--rip-danger)' : 'var(--rip-gray-900)' ?>;" data-kpi="tokens_triggered"><?= number_format((int) $intelSummary['tokens_triggered']) ?></div>
            <div class="rip-stat-card__hint">of <?= number_format((int) $intelSummary['tokens_issued']) ?> issued canaries</div>
        </div>
    </a>
</div>

<!-- Activity Chart + Severity Breakdown -->
<?php
    $chartRanges = $chart_data_ranges ?? ['24h' => $chart_data ?? [], '7d' => [], '30d' => []];
    $rangeMeta = [
        '24h' => ['title' => 'Last 24 Hours', 'tab' => '24h',     'every' => 4],
        '7d'  => ['title' => 'Last 7 Days',   'tab' => '7 days',  'every' => 1],
        '30d' => ['title' => 'Last 30 Days',  'tab' => '30 days', 'every' => 5],
    ];
    $sev = $severity_breakdown ?? ['buckets' => ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0], 'total' => 0, 'days' => 7];
    $sevTotal = (int) $sev['total'];
    $sevMeta = [
        'critical' => 'Critical (8-10)',
        'high'     => 'High (5-7)',
        'medium'   => 'Medium (3-4)',
        'low'      => 'Low (1-2)',
    ];
?>
<div class="rip-grid rip-grid--main">
    <div class="rip-card" data-rip-activity-card>
        <div class="rip-card__header rip-card__header--flex">
            <span data-rip-activity-title>Activity (<?= htmlspecialchars($rangeMeta['24h']['title'], ENT_QUOTES, 'UTF-8') ?>)</span>
            <div class="rip-seg" role="tablist" aria-label="Activity range">
                <?php foreach ($rangeMeta as $rangeKey => $meta): ?>
                    <button type="button" role="tab" class="rip-seg__btn"
                            data-rip-activity-tab="<?= htmlspecialchars($rangeKey, ENT_QUOTES, 'UTF-8') ?>"
                            aria-selected="<?= $rangeKey === '24h' ? 'true' : 'false' ?>">
                        <?= htmlspecialchars($meta['tab'], ENT_QUOTES, 'UTF-8') ?>
                    </button>
                <?php endforeach; ?>
            </div>
        </div>
        <?php foreach ($rangeMeta as $rangeKey => $meta): ?>
            <?php
                $bars = $chartRanges[$rangeKey] ?? [];
                $peak = 0;
                $rangeTotal = 0;
                foreach ($bars as $bar) {
                    $rangeTotal += (int) ($bar['count'] ?? 0);
                    $peak = max($peak, (int) ($bar['count'] ?? 0));
                }
                $maxCount = max(1, $peak);
            ?>
            <div data-rip-activity-panel="<?= htmlspecialchars($rangeKey, ENT_QUOTES, 'UTF-8') ?>"
                 data-rip-activity-title-text="<?= htmlspecialchars('Activity (' . $meta['title'] . ')', ENT_QUOTES, 'UTF-8') ?>"
                 style="display:<?= $rangeKey === '24h' ? 'block' : 'none' ?>;">
                <div class="rip-chart__meta"><?= number_format($rangeTotal) ?> events &middot; peak <?= number_format($peak) ?></div>
                <div class="rip-chart__bars">
                    <?php foreach ($bars as $bar): ?>
                        <?php
                            $count = (int) ($bar['count'] ?? 0);
                            $pct = $maxCount > 0 ? ($count / $maxCount) * 100 : 0;
                        ?>
                        <div class="rip-chart__col" title="<?= htmlspecialchars($bar['label'] ?? '', ENT_QUOTES, 'UTF-8') ?>: <?= $count ?> events">
                            <div class="rip-chart__bar<?= $count === 0 ? ' rip-chart__bar--zero' : '' ?>" style="height:<?= max(2, $pct) ?>%;"></div>
                        </div>
                    <?php endforeach; ?>
                </div>
                <div class="rip-chart__labels">
                    <?php foreach ($bars as $i => $bar): ?>
                        <div class="rip-chart__label"><?= $i % $meta['every'] === 0 ? htmlspecialchars($bar['label'] ?? '', ENT_QUOTES, 'UTF-8') : '' ?></div>
                    <?php endforeach; ?>
                </div>
            </div>
        <?php endforeach; ?>
    </div>

    <div class="rip-card">
        <div class="rip-card__header rip-card__header--flex">
            <span>Severity</span>
            <span class="rip-card__header-meta">last <?= (int) $sev['days'] ?> days</span>
        </div>
        <?php if ($sevTotal > 0): ?>
            <div class="rip-meter">
                <?php foreach ($sev['buckets'] as $sevKey => $sevCount): ?>
                    <?php if ($sevCount > 0): ?>
                        <div class="rip-meter__seg rip-meter__seg--<?= $sevKey ?>" style="width:<?= ($sevCount / $sevTotal) * 100 ?>%;" title="<?= htmlspecialchars($sevMeta[$sevKey], ENT_QUOTES, 'UTF-8') ?>: <?= number_format($sevCount) ?>"></div>
                    <?php endif; ?>
                <?php endforeach; ?>
            </div>
            <div class="rip-legend">
                <?php foreach ($sev['buckets'] as $sevKey => $sevCount): ?>
                    <div class="rip-legend__row">
                        <span class="rip-legend__dot rip-legend__dot--<?= $sevKey ?>"></span>
                        <span class="rip-legend__label"><?= htmlspecialchars($sevMeta[$sevKey], ENT_QUOTES, 'UTF-8') ?></span>
                        <span class="rip-legend__value"><?= number_format($sevCount) ?></span>
                        <span class="rip-legend__pct"><?= $sevTotal > 0 ? round(($sevCount / $sevTotal) * 100) : 0 ?>%</span>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php else: ?>
            <div class="rip-empty-state">
                <div class="rip-empty-state__text">No events in the last <?= (int) $sev['days'] ?> days.</div>
            </div>
        <?php endif; ?>
    </div>
</div>

<!-- Threat Intel -->
<?php
    $recentTriggered = $intel['recent_triggered'] ?? [];
    $recentCaptures = $intel['recent_captures'] ?? [];
?>
<div class="rip-intel-card">
    <div class="rip-intel-card__header">
        <span class="rip-intel-card__title">
            <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 1a4.5 4.5 0 00-4.5 4.5V9H5a2 2 0 00-2 2v6a2 2 0 002 2h10a2 2 0 002-2v-6a2 2 0 00-2-2h-.5V5.5A4.5 4.5 0 0010 1zm3 8V5.5a3 3 0 10-6 0V9h6z" clip-rule="evenodd"/></svg>
            Threat Intel
        </span>
        <div class="rip-intel-card__chips">
            <span class="rip-chip"><strong><?= number_format((int) $intelSummary['tokens_issued']) ?></strong> canaries armed</span>
            <span class="rip-chip<?= ((int) $intelSummary['tokens_triggered']) > 0 ? ' rip-chip--danger' : '' ?>"><strong><?= number_format((int) $intelSummary['tokens_triggered']) ?></strong> triggered</span>
            <span class="rip-chip"><strong><?= number_format((int) $intelSummary['captures']) ?></strong> payloads (<?= $fmtSize((int) $intelSummary['capture_bytes']) ?>)</span>
            <a href="<?= $base ?>/intel" class="rip-link--light">Open Threat Intel &rarr;</a>
        </div>
    </div>
    <div class="rip-intel-card__grid">
        <div>
            <div class="rip-intel-card__subtitle">Latest Triggered Honeytokens</div>
            <?php if (!empty($recentTriggered)): ?>
                <ul class="rip-feed">
                    <?php foreach ($recentTriggered as $t): ?>
                        <li class="rip-feed__item">
                            <span class="rip-feed__time"><?= htmlspecialchars($fmtShortTs($t['triggered_at'] ?? null), ENT_QUOTES, 'UTF-8') ?></span>
                            <span class="rip-feed__text">
                                <span class="rip-feed__mono"><?= htmlspecialchars(str_replace('_', ' ', (string) $t['token_type']), ENT_QUOTES, 'UTF-8') ?></span>
                                reused by <span class="rip-feed__mono"><?= htmlspecialchars((string) ($t['triggered_by_ip'] ?? '?'), ENT_QUOTES, 'UTF-8') ?></span>
                                <?php if ((int) ($t['trigger_count'] ?? 0) > 1): ?>(<?= (int) $t['trigger_count'] ?>&times;)<?php endif; ?>
                            </span>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php else: ?>
                <div class="rip-feed__empty">No canary credentials have been reused yet. Leaked tokens stay armed until an attacker replays them.</div>
            <?php endif; ?>
        </div>
        <div>
            <div class="rip-intel-card__subtitle">Latest Captured Payloads</div>
            <?php if (!empty($recentCaptures)): ?>
                <ul class="rip-feed">
                    <?php foreach ($recentCaptures as $c): ?>
                        <li class="rip-feed__item">
                            <span class="rip-feed__time"><?= htmlspecialchars($fmtShortTs($c['timestamp'] ?? null), ENT_QUOTES, 'UTF-8') ?></span>
                            <span class="rip-feed__text">
                                <span class="rip-feed__mono"><?= htmlspecialchars(str_replace('_', ' ', (string) $c['capture_type']), ENT_QUOTES, 'UTF-8') ?></span>
                                from <span class="rip-feed__mono"><?= htmlspecialchars((string) $c['ip'], ENT_QUOTES, 'UTF-8') ?></span>
                                <?php if (!empty($c['filename'])): ?>&mdash; <?= htmlspecialchars((string) $c['filename'], ENT_QUOTES, 'UTF-8') ?><?php endif; ?>
                                (<?= $fmtSize((int) ($c['size'] ?? 0)) ?>)
                            </span>
                            <a href="<?= $base ?>/intel/capture/<?= (int) $c['id'] ?>" class="rip-link--light">View</a>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php else: ?>
                <div class="rip-feed__empty">No payloads captured yet. Fake-admin uploads, webshell POSTs and DB-admin logins land here.</div>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- Visitor Breakdown + Top Bots -->
<?php
    $vStats = $visitor_stats ?? ['counts' => [], 'top_bots' => []];
    $vCounts = $vStats['counts'] ?? [];
    $vTopBots = $vStats['top_bots'] ?? [];
    $vTotal = array_sum($vCounts);
    $vTypeLabels = [
        'good_bot' => ['label' => 'Good Bots', 'raw' => '#10b981'],
        'ai_agent' => ['label' => 'AI Agents', 'raw' => '#8b5cf6'],
        'bad_bot'  => ['label' => 'Bad Bots', 'raw' => '#ef4444'],
        'hacker'   => ['label' => 'Hackers', 'raw' => '#f59e0b'],
        'human'    => ['label' => 'Humans', 'raw' => '#6366f1'],
    ];
?>
<div class="rip-grid rip-grid--2">
    <div class="rip-card">
        <div class="rip-card__header rip-card__header--flex">
            <span>Visitor Breakdown (24h)</span>
            <a href="<?= $base ?>/visitors" class="rip-link rip-card__header-meta">View All &rarr;</a>
        </div>
        <?php if ($vTotal > 0): ?>
        <div class="rip-bar-list">
            <?php foreach ($vTypeLabels as $vType => $vInfo): ?>
                <?php $vCount = $vCounts[$vType] ?? 0; $vPct = $vTotal > 0 ? ($vCount / $vTotal) * 100 : 0; ?>
                <div class="rip-bar-list__row">
                    <span class="rip-bar-list__label"><?= htmlspecialchars($vInfo['label'], ENT_QUOTES, 'UTF-8') ?></span>
                    <div class="rip-bar-list__track">
                        <div class="rip-bar-list__fill" style="width:<?= max(0, $vPct) ?>%; background:<?= htmlspecialchars($vInfo['raw'], ENT_QUOTES, 'UTF-8') ?>;"></div>
                    </div>
                    <span class="rip-bar-list__value"><?= number_format($vCount) ?></span>
                </div>
            <?php endforeach; ?>
        </div>
        <?php else: ?>
        <div class="rip-empty-state">
            <div class="rip-empty-state__text">No visitor data yet.</div>
        </div>
        <?php endif; ?>
    </div>

    <div class="rip-card">
        <div class="rip-card__header">Top Bots &amp; Agents (24h)</div>
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

<!-- Top IPs / Categories / Targeted Paths -->
<div class="rip-grid rip-grid--3">
    <div class="rip-card">
        <div class="rip-card__header">Top Attacking IPs</div>
        <table class="rip-table">
            <thead><tr><th>IP Address</th><th style="text-align:right;">Events</th></tr></thead>
            <tbody>
            <?php if (!empty($stats['top_ips'])): ?>
                <?php foreach ($stats['top_ips'] as $row): ?>
                    <tr>
                        <td>
                            <a href="<?= $base ?>/logs?ip=<?= urlencode($row['ip']) ?>" class="rip-link" style="font-family:var(--rip-font-mono); font-size:var(--rip-font-size-sm);">
                                <?= htmlspecialchars($row['ip'], ENT_QUOTES, 'UTF-8') ?>
                            </a>
                            <a href="https://reportedip.com/ip/<?= urlencode($row['ip']) ?>/" target="_blank" rel="noopener" class="rip-ip-external" title="View on reportedip.com">&#8599;</a>
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

    <div class="rip-card">
        <div class="rip-card__header">Top Categories</div>
        <table class="rip-table">
            <thead><tr><th>Categories</th><th style="text-align:right;">Events</th></tr></thead>
            <tbody>
            <?php if (!empty($stats['top_categories'])): ?>
                <?php foreach (array_slice($stats['top_categories'], 0, 8) as $row): ?>
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

    <div class="rip-card">
        <div class="rip-card__header rip-card__header--flex">
            <span>Top Targeted Paths</span>
            <span class="rip-card__header-meta">last 7 days</span>
        </div>
        <?php if (!empty($top_uris)): ?>
            <?php
                $uriMax = 1;
                foreach ($top_uris as $u) {
                    $uriMax = max($uriMax, (int) $u['cnt']);
                }
            ?>
            <div class="rip-bar-list">
                <?php foreach ($top_uris as $u): ?>
                    <div class="rip-bar-list__row">
                        <span class="rip-bar-list__label rip-bar-list__label--wide" title="<?= htmlspecialchars((string) $u['path'], ENT_QUOTES, 'UTF-8') ?>"><?= htmlspecialchars((string) $u['path'], ENT_QUOTES, 'UTF-8') ?></span>
                        <div class="rip-bar-list__track">
                            <div class="rip-bar-list__fill" style="width:<?= ((int) $u['cnt'] / $uriMax) * 100 ?>%;"></div>
                        </div>
                        <span class="rip-bar-list__value"><?= number_format((int) $u['cnt']) ?></span>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php else: ?>
            <div class="rip-empty-state">
                <div class="rip-empty-state__text">No data yet.</div>
            </div>
        <?php endif; ?>
    </div>
</div>

<?php endif; ?>

<!-- Whitelist Section -->
<?php if (($active_tab ?? '') === 'whitelist'): ?>
<div class="rip-card" id="whitelist-section">
    <div class="rip-card__header">IP Whitelist</div>
    <form method="post" action="<?= $base ?>/whitelist" style="display:flex; gap:8px; margin-bottom:16px; flex-wrap:wrap;">
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
                        <form method="post" action="<?= $base ?>/whitelist" style="display:inline;">
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
    <div class="rip-card__header rip-card__header--flex">
        <span>Recent Attacks</span>
        <a href="<?= $base ?>/logs" class="rip-link rip-card__header-meta">View All &rarr;</a>
    </div>
    <div style="overflow-x:auto;">
        <table class="rip-table">
            <thead><tr><th>IP</th><th>Categories</th><th>URI</th><th>Method</th><th>Timestamp</th><th>Status</th></tr></thead>
            <tbody>
            <?php if (!empty($recent_logs)): ?>
                <?php foreach (array_slice($recent_logs, 0, 12) as $log): ?>
                    <tr>
                        <td style="font-family:var(--rip-font-mono); white-space:nowrap;">
                            <a href="<?= $base ?>/logs?ip=<?= urlencode($log['ip']) ?>" class="rip-link"><?= htmlspecialchars($log['ip'], ENT_QUOTES, 'UTF-8') ?></a>
                            <a href="https://reportedip.com/ip/<?= urlencode($log['ip']) ?>/" target="_blank" rel="noopener" class="rip-ip-external" title="View on reportedip.com">&#8599;</a>
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
    $pillClass = in_array($cronHealth, ['healthy', 'warning', 'critical'], true) ? $cronHealth : 'unknown';
    $webhooks = $webhook_summary ?? ['total' => 0, 'enabled' => 0, 'failing' => 0];
?>
<div class="rip-card">
    <div class="rip-card__header rip-card__header--flex">
        <span>
            Queue Processing
            <span class="rip-badge" style="margin-left:8px; background:<?= $queueMode === 'web' ? 'var(--rip-primary)' : 'var(--rip-gray-500)' ?>; color:#fff; font-size:var(--rip-font-size-xs); font-weight:500; padding:2px 8px;"><?= $queueMode === 'web' ? 'Web Mode' : 'Cron Mode' ?></span>
            <?php if ($webhooks['enabled'] > 0): ?>
                <span class="rip-badge" style="margin-left:4px; background:var(--rip-gray-100); color:var(--rip-gray-600); font-size:var(--rip-font-size-xs); font-weight:500; padding:2px 8px;" title="<?= (int) $webhooks['failing'] ?> failing">
                    <?= (int) $webhooks['enabled'] ?> webhook<?= $webhooks['enabled'] !== 1 ? 's' : '' ?><?= $webhooks['failing'] > 0 ? ' (' . (int) $webhooks['failing'] . ' failing)' : '' ?>
                </span>
            <?php endif; ?>
        </span>
        <span class="rip-status-pill rip-status-pill--<?= $pillClass ?>">
            <span class="rip-status-pill__dot"></span>
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

        <?php if (!empty($recent_failures)): ?>
        <div style="margin-top:12px; padding-top:12px; border-top:1px solid var(--rip-gray-100);">
            <strong style="color:var(--rip-gray-600); font-size:var(--rip-font-size-sm);">Recent Failures (Last <?= count($recent_failures) ?>)</strong>
            <div style="overflow-x:auto; margin-top:8px;">
                <table class="rip-table rip-table--compact">
                    <thead><tr><th>Time</th><th>IP</th><th>URI</th><th>Reason</th><th style="text-align:right;">Attempts</th><th>Status</th></tr></thead>
                    <tbody>
                    <?php foreach ($recent_failures as $f): ?>
                        <?php $reason = (string) ($f['last_failure_reason'] ?? ''); ?>
                        <tr>
                            <td style="white-space:nowrap; font-size:var(--rip-font-size-xs); color:var(--rip-gray-500);"><?= htmlspecialchars((string) ($f['last_failure_at'] ?? ''), ENT_QUOTES, 'UTF-8') ?></td>
                            <td style="font-family:var(--rip-font-mono); white-space:nowrap;">
                                <a href="<?= $base ?>/logs?ip=<?= urlencode((string) $f['ip']) ?>" class="rip-link"><?= htmlspecialchars((string) $f['ip'], ENT_QUOTES, 'UTF-8') ?></a>
                                <a href="https://reportedip.com/ip/<?= urlencode((string) $f['ip']) ?>/" target="_blank" rel="noopener" class="rip-ip-external" title="View on reportedip.com">&#8599;</a>
                            </td>
                            <td style="max-width:220px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="<?= htmlspecialchars((string) ($f['request_uri'] ?? ''), ENT_QUOTES, 'UTF-8') ?>">
                                <?= htmlspecialchars((string) ($f['request_uri'] ?? ''), ENT_QUOTES, 'UTF-8') ?>
                            </td>
                            <td style="font-family:var(--rip-font-mono); font-size:var(--rip-font-size-xs); color:var(--rip-danger-text); max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="<?= htmlspecialchars($reason, ENT_QUOTES, 'UTF-8') ?>">
                                <?= htmlspecialchars($reason, ENT_QUOTES, 'UTF-8') ?>
                            </td>
                            <td style="text-align:right; font-weight:600;"><?= number_format((int) ($f['failed_attempts'] ?? 0)) ?></td>
                            <td>
                                <?php $sent = (int) ($f['sent'] ?? 0); ?>
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
                    </tbody>
                </table>
            </div>
        </div>
        <?php endif; ?>

    <?php else: ?>
        <!-- Queue not yet active -->
        <div style="padding:12px 0; font-size:var(--rip-font-size-base); color:var(--rip-gray-500);">
            <?php if ($queueMode === 'web'): ?>
                Web cron mode is active. The queue is processed automatically during page visits.
            <?php else: ?>
                The cron job has not run yet. Set it up to automatically send pending reports to the reportedip.com API.
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
    <div class="rip-kv">
        <div>
            <div class="rip-kv__key">Version</div>
            <div class="rip-kv__val"><?= htmlspecialchars($system['app_version'] ?? '?', ENT_QUOTES, 'UTF-8') ?></div>
        </div>
        <div>
            <div class="rip-kv__key">PHP Version</div>
            <div class="rip-kv__val"><?= htmlspecialchars($system['php_version'] ?? '', ENT_QUOTES, 'UTF-8') ?></div>
        </div>
        <div>
            <div class="rip-kv__key">CMS Profile</div>
            <div class="rip-kv__val"><?= htmlspecialchars(ucfirst($system['cms_profile'] ?? ''), ENT_QUOTES, 'UTF-8') ?></div>
        </div>
        <div>
            <div class="rip-kv__key">API Configured</div>
            <div class="rip-kv__val"><?= ($system['api_configured'] ?? false) ? '<span style="color:var(--rip-success);">Yes</span>' : '<span style="color:var(--rip-danger);">No</span>' ?></div>
        </div>
        <div>
            <div class="rip-kv__key">Database Size</div>
            <div class="rip-kv__val"><?= htmlspecialchars($system['db_size'] ?? '0 B', ENT_QUOTES, 'UTF-8') ?></div>
        </div>
        <div>
            <div class="rip-kv__key">Log Retention</div>
            <div class="rip-kv__val"><?= (int)($system['retention_days'] ?? 90) ?> days</div>
        </div>
    </div>
</div>

<script>
(function() {
    // Activity chart range tabs
    var card = document.querySelector('[data-rip-activity-card]');
    if (card) {
        var titleEl = card.querySelector('[data-rip-activity-title]');
        card.querySelectorAll('[data-rip-activity-tab]').forEach(function(btn) {
            btn.addEventListener('click', function() {
                var range = btn.getAttribute('data-rip-activity-tab');
                card.querySelectorAll('[data-rip-activity-tab]').forEach(function(b) {
                    b.setAttribute('aria-selected', b === btn ? 'true' : 'false');
                });
                card.querySelectorAll('[data-rip-activity-panel]').forEach(function(p) {
                    var match = p.getAttribute('data-rip-activity-panel') === range;
                    p.style.display = match ? 'block' : 'none';
                    if (match && titleEl) {
                        titleEl.textContent = p.getAttribute('data-rip-activity-title-text') || titleEl.textContent;
                    }
                });
            });
        });
    }

    // Live KPI refresh via the stats API (every 60s)
    var adminPath = <?= json_encode($admin_path ?? '') ?>;
    if (!adminPath || !window.fetch || !document.querySelector('[data-kpi]')) {
        return;
    }
    function setKpi(name, value) {
        var el = document.querySelector('[data-kpi="' + name + '"]');
        if (el && typeof value === 'number') {
            el.textContent = value.toLocaleString('en-US');
        }
    }
    setInterval(function() {
        fetch(adminPath + '/api/stats', { credentials: 'same-origin' })
            .then(function(r) { return r.ok ? r.json() : null; })
            .then(function(d) {
                if (!d || !d.stats) return;
                setKpi('total', d.stats.total);
                setKpi('today', d.stats.today);
                setKpi('unique_ips', d.stats.unique_ips);
                setKpi('pending', d.stats.pending);
                if (d.intel) {
                    setKpi('tokens_triggered', d.intel.tokens_triggered);
                }
            })
            .catch(function() { /* offline or session expired: keep last values */ });
    }, 60000);
})();
</script>

<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
?>
