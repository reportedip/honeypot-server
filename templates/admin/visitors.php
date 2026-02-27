<?php
/**
 * Admin Visitors/Bot Log Template
 *
 * Variables: $entries, $total, $page, $per_page, $total_pages,
 *            $admin_path, $filters, $stats
 */

$page_title = 'Visitors';
$active_tab = 'visitors';

$typeColors = [
    'good_bot' => ['badge' => 'rip-badge--good-bot'],
    'ai_agent' => ['badge' => 'rip-badge--ai-agent'],
    'bad_bot'  => ['badge' => 'rip-badge--bad-bot'],
    'hacker'   => ['badge' => 'rip-badge--hacker'],
    'human'    => ['badge' => 'rip-badge--human'],
];

$typeStatColors = [
    'good_bot' => 'var(--rip-success)',
    'ai_agent' => '#8B5CF6',
    'bad_bot'  => 'var(--rip-danger)',
    'hacker'   => 'var(--rip-warning)',
    'human'    => 'var(--rip-primary)',
];

ob_start();
?>

<!-- Summary Cards -->
<div style="display:grid; grid-template-columns: repeat(5, 1fr); gap:12px; margin-bottom:24px;">
    <?php foreach ($stats as $type => $count): ?>
        <?php $statColor = $typeStatColors[$type] ?? 'var(--rip-gray-600)'; ?>
        <div class="rip-stat-card" style="flex-direction:column; text-align:center; gap:4px;">
            <div class="rip-stat-card__label"><?= htmlspecialchars(str_replace('_', ' ', $type), ENT_QUOTES, 'UTF-8') ?></div>
            <div class="rip-stat-card__value" style="font-size:var(--rip-font-size-2xl); color:<?= $statColor ?>;"><?= number_format($count) ?></div>
        </div>
    <?php endforeach; ?>
</div>

<!-- Filters -->
<div class="rip-card" style="margin-bottom:16px;">
    <form method="get" action="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/visitors" class="rip-filter-bar">
        <div style="min-width:120px;">
            <label class="rip-label">Type</label>
            <select name="type" class="rip-select">
                <option value="">All</option>
                <?php foreach (['good_bot', 'ai_agent', 'bad_bot', 'hacker', 'human'] as $t): ?>
                    <option value="<?= $t ?>" <?= ($filters['type'] ?? '') === $t ? 'selected' : '' ?>><?= htmlspecialchars(str_replace('_', ' ', ucfirst($t)), ENT_QUOTES, 'UTF-8') ?></option>
                <?php endforeach; ?>
            </select>
        </div>
        <div style="min-width:150px;">
            <label class="rip-label">Bot Name</label>
            <input type="text" name="bot_name" value="<?= htmlspecialchars($filters['bot_name'] ?? '', ENT_QUOTES, 'UTF-8') ?>" placeholder="e.g. Googlebot" class="rip-input">
        </div>
        <div style="min-width:140px;">
            <label class="rip-label">IP</label>
            <input type="text" name="ip" value="<?= htmlspecialchars($filters['ip'] ?? '', ENT_QUOTES, 'UTF-8') ?>" placeholder="e.g. 66.249.65.1" class="rip-input">
        </div>
        <button type="submit" class="rip-button rip-button--primary">Filter</button>
        <?php if (!empty($filters['type']) || !empty($filters['bot_name']) || !empty($filters['ip'])): ?>
            <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/visitors" class="rip-button rip-button--ghost">Clear</a>
        <?php endif; ?>
    </form>
</div>

<!-- Visitors Table -->
<div class="rip-card">
    <div class="rip-card__header">
        Visitor Log
        <span style="float:right; font-size:var(--rip-font-size-sm); font-weight:400; color:var(--rip-gray-500);"><?= number_format($total) ?> entries</span>
    </div>
    <div style="overflow-x:auto;">
        <table class="rip-table">
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>IP</th>
                    <th>Bot Name</th>
                    <th>Type</th>
                    <th>URI</th>
                    <th>Method</th>
                </tr>
            </thead>
            <tbody>
            <?php if (!empty($entries)): ?>
                <?php foreach ($entries as $entry): ?>
                    <?php $badgeClass = $typeColors[$entry['visitor_type']]['badge'] ?? ''; ?>
                    <tr>
                        <td style="white-space:nowrap; font-size:var(--rip-font-size-sm); color:var(--rip-gray-500);"><?= htmlspecialchars($entry['timestamp'] ?? '', ENT_QUOTES, 'UTF-8') ?></td>
                        <td style="font-family:var(--rip-font-mono); white-space:nowrap;">
                            <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/visitors?ip=<?= urlencode($entry['ip']) ?>" class="rip-link">
                                <?= htmlspecialchars($entry['ip'], ENT_QUOTES, 'UTF-8') ?>
                            </a>
                        </td>
                        <td><?= htmlspecialchars($entry['bot_name'] ?? '', ENT_QUOTES, 'UTF-8') ?></td>
                        <td>
                            <span class="rip-badge <?= $badgeClass ?>">
                                <?= htmlspecialchars(str_replace('_', ' ', $entry['visitor_type']), ENT_QUOTES, 'UTF-8') ?>
                            </span>
                        </td>
                        <td style="max-width:300px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:var(--rip-font-size-sm);" title="<?= htmlspecialchars($entry['request_uri'] ?? '', ENT_QUOTES, 'UTF-8') ?>">
                            <?= htmlspecialchars($entry['request_uri'] ?? '', ENT_QUOTES, 'UTF-8') ?>
                        </td>
                        <td><span class="rip-badge rip-badge--method"><?= htmlspecialchars($entry['request_method'] ?? 'GET', ENT_QUOTES, 'UTF-8') ?></span></td>
                    </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr><td colspan="6" class="rip-empty-state__text" style="text-align:center; padding:20px;">No visitor entries yet.</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<?php if ($total_pages > 1): ?>
<div class="rip-pagination">
    <?php
    $queryBase = $admin_path . '/visitors?';
    $filterParams = http_build_query(array_filter($filters));
    if ($filterParams !== '') {
        $queryBase .= $filterParams . '&';
    }
    ?>
    <?php if ($page > 1): ?>
        <a href="<?= htmlspecialchars($queryBase . 'page=' . ($page - 1), ENT_QUOTES, 'UTF-8') ?>">&laquo;</a>
    <?php endif; ?>
    <?php for ($i = max(1, $page - 3); $i <= min($total_pages, $page + 3); $i++): ?>
        <?php if ($i === $page): ?>
            <span class="current"><?= $i ?></span>
        <?php else: ?>
            <a href="<?= htmlspecialchars($queryBase . 'page=' . $i, ENT_QUOTES, 'UTF-8') ?>"><?= $i ?></a>
        <?php endif; ?>
    <?php endfor; ?>
    <?php if ($page < $total_pages): ?>
        <a href="<?= htmlspecialchars($queryBase . 'page=' . ($page + 1), ENT_QUOTES, 'UTF-8') ?>">&raquo;</a>
    <?php endif; ?>
</div>
<?php endif; ?>

<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
?>
