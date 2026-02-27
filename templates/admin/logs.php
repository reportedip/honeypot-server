<?php
/**
 * Admin Log Viewer Template
 *
 * Variables: $logs, $total, $page, $pages, $per_page,
 *            $filters, $categories, $methods, $admin_path,
 *            $categoryRegistry (class name for static calls)
 */

$page_title = 'Attack Logs';
$active_tab = 'logs';

ob_start();
?>

<!-- Filters -->
<div class="rip-card">
    <form method="get" action="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/logs" class="rip-filter-bar">
        <div style="flex:1; min-width:150px;">
            <label class="rip-label">Search</label>
            <input type="text" name="search" value="<?= htmlspecialchars($filters['search'] ?? '', ENT_QUOTES, 'UTF-8') ?>" placeholder="IP, URI, comment..." class="rip-input">
        </div>
        <div style="min-width:120px;">
            <label class="rip-label">IP Address</label>
            <input type="text" name="ip" value="<?= htmlspecialchars($filters['ip'] ?? '', ENT_QUOTES, 'UTF-8') ?>" placeholder="Filter by IP" class="rip-input">
        </div>
        <div style="min-width:170px;">
            <label class="rip-label">Category</label>
            <select name="category" class="rip-select">
                <option value="">All</option>
                <?php foreach ($categories ?? [] as $cat): ?>
                    <option value="<?= htmlspecialchars($cat['id'], ENT_QUOTES, 'UTF-8') ?>" <?= ($filters['category'] ?? '') === $cat['id'] ? 'selected' : '' ?>>
                        <?= htmlspecialchars($cat['id'] . ' - ' . $cat['name'], ENT_QUOTES, 'UTF-8') ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>
        <div style="min-width:80px;">
            <label class="rip-label">Method</label>
            <select name="method" class="rip-select">
                <option value="">All</option>
                <?php foreach ($methods ?? [] as $m): ?>
                    <option value="<?= htmlspecialchars($m, ENT_QUOTES, 'UTF-8') ?>" <?= ($filters['method'] ?? '') === $m ? 'selected' : '' ?>>
                        <?= htmlspecialchars($m, ENT_QUOTES, 'UTF-8') ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>
        <div style="min-width:100px;">
            <label class="rip-label">Status</label>
            <select name="sent" class="rip-select">
                <option value="">All</option>
                <option value="0" <?= ($filters['sent'] ?? '') === '0' ? 'selected' : '' ?>>Pending</option>
                <option value="1" <?= ($filters['sent'] ?? '') === '1' ? 'selected' : '' ?>>Sent</option>
                <option value="2" <?= ($filters['sent'] ?? '') === '2' ? 'selected' : '' ?>>Whitelisted</option>
            </select>
        </div>
        <button type="submit" class="rip-button rip-button--primary">Filter</button>
        <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/logs" class="rip-button rip-button--ghost">Clear</a>
    </form>
</div>

<!-- Results -->
<div class="rip-card">
    <div class="rip-card__header">
        <?= number_format($total) ?> log entries found
        <?php if ($pages > 1): ?>
            &mdash; Page <?= $page ?> of <?= $pages ?>
        <?php endif; ?>
    </div>
    <div style="overflow-x:auto;">
        <table class="rip-table">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>IP</th>
                    <th>Categories</th>
                    <th>Comment</th>
                    <th>URI</th>
                    <th>Method</th>
                    <th>User-Agent</th>
                    <th>Timestamp</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
            <?php if (!empty($logs)): ?>
                <?php foreach ($logs as $log): ?>
                    <tr>
                        <td style="color:var(--rip-gray-400); font-size:var(--rip-font-size-sm);">
                            <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/logs/view/<?= (int)$log['id'] ?>" class="rip-link--muted" style="text-decoration:none;"><?= (int)$log['id'] ?></a>
                        </td>
                        <td style="font-family:var(--rip-font-mono); white-space:nowrap;">
                            <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/logs?ip=<?= urlencode($log['ip']) ?>" class="rip-link"><?= htmlspecialchars($log['ip'], ENT_QUOTES, 'UTF-8') ?></a>
                            <a href="https://reportedip.de/ip/<?= urlencode($log['ip']) ?>/" target="_blank" rel="noopener" class="rip-ip-external" title="View on reportedip.de">&#8599;</a>
                        </td>
                        <td><?= $categoryRegistry::formatBadges($log['categories'] ?? '') ?></td>
                        <td style="max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:var(--rip-font-size-sm);" title="<?= htmlspecialchars($log['comment'] ?? '', ENT_QUOTES, 'UTF-8') ?>">
                            <?= htmlspecialchars($log['comment'] ?? '', ENT_QUOTES, 'UTF-8') ?>
                        </td>
                        <td style="max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-family:var(--rip-font-mono); font-size:var(--rip-font-size-sm);" title="<?= htmlspecialchars($log['request_uri'] ?? '', ENT_QUOTES, 'UTF-8') ?>">
                            <?= htmlspecialchars($log['request_uri'] ?? '', ENT_QUOTES, 'UTF-8') ?>
                        </td>
                        <td><span class="rip-badge rip-badge--method"><?= htmlspecialchars($log['request_method'] ?? 'GET', ENT_QUOTES, 'UTF-8') ?></span></td>
                        <td style="max-width:160px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:var(--rip-font-size-xs); color:var(--rip-gray-500);" title="<?= htmlspecialchars($log['user_agent'] ?? '', ENT_QUOTES, 'UTF-8') ?>">
                            <?= htmlspecialchars($log['user_agent'] ?? '', ENT_QUOTES, 'UTF-8') ?>
                        </td>
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
                <tr><td colspan="9" class="rip-empty-state__text" style="text-align:center; padding:24px;">No log entries match your filters.</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>

    <!-- Pagination -->
    <?php if ($pages > 1): ?>
        <div class="rip-pagination">
            <?php
            // Build query string preserving filters
            $queryBase = [];
            foreach ($filters as $k => $v) {
                if ($v !== '' && $v !== null) {
                    $queryBase[$k] = $v;
                }
            }

            $buildUrl = function (int $p) use ($admin_path, $queryBase): string {
                $queryBase['page'] = $p;
                return htmlspecialchars($admin_path . '/logs?' . http_build_query($queryBase), ENT_QUOTES, 'UTF-8');
            };
            ?>

            <?php if ($page > 1): ?>
                <a href="<?= $buildUrl(1) ?>">&laquo;</a>
                <a href="<?= $buildUrl($page - 1) ?>">&lsaquo;</a>
            <?php endif; ?>

            <?php
            $start = max(1, $page - 3);
            $end = min($pages, $page + 3);
            ?>
            <?php for ($i = $start; $i <= $end; $i++): ?>
                <?php if ($i === $page): ?>
                    <span class="current"><?= $i ?></span>
                <?php else: ?>
                    <a href="<?= $buildUrl($i) ?>"><?= $i ?></a>
                <?php endif; ?>
            <?php endfor; ?>

            <?php if ($page < $pages): ?>
                <a href="<?= $buildUrl($page + 1) ?>">&rsaquo;</a>
                <a href="<?= $buildUrl($pages) ?>">&raquo;</a>
            <?php endif; ?>
        </div>
    <?php endif; ?>
</div>

<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
?>
