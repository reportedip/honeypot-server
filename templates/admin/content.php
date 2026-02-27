<?php
/**
 * Admin Content List Template
 *
 * Variables: $entries, $total, $page, $per_page, $total_pages,
 *            $admin_path, $csrf_token, $cms_profile
 */

$page_title = 'Content';
$active_tab = 'content';

// Flash message
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
$message = $_SESSION['flash_message'] ?? '';
$message_type = $_SESSION['flash_type'] ?? 'success';
unset($_SESSION['flash_message'], $_SESSION['flash_type']);

ob_start();
?>

<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
    <div>
        <strong><?= number_format($total) ?></strong> content entries (<?= htmlspecialchars(ucfirst($cms_profile), ENT_QUOTES, 'UTF-8') ?>)
    </div>
    <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/content/generate" class="rip-button rip-button--primary">Generate Content</a>
</div>

<?php if (empty($entries)): ?>
<div class="rip-card">
    <div class="rip-empty-state">
        <div class="rip-empty-state__icon">&#9998;</div>
        <p class="rip-empty-state__title">No content generated yet.</p>
        <div class="rip-empty-state__actions">
            <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/content/generate" class="rip-button rip-button--primary rip-button--lg">Generate Your First Content</a>
        </div>
    </div>
</div>
<?php else: ?>
<div class="rip-card">
    <div style="overflow-x:auto;">
        <table class="rip-table">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Title</th>
                    <th>Slug</th>
                    <th>Author</th>
                    <th>Status</th>
                    <th>Published</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($entries as $entry): ?>
                <tr>
                    <td><?= (int) $entry['id'] ?></td>
                    <td style="max-width:250px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
                        <?= htmlspecialchars($entry['title'], ENT_QUOTES, 'UTF-8') ?>
                    </td>
                    <td style="font-family:var(--rip-font-mono); font-size:var(--rip-font-size-sm); max-width:180px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
                        <?= htmlspecialchars($entry['slug'], ENT_QUOTES, 'UTF-8') ?>
                    </td>
                    <td><?= htmlspecialchars($entry['author'], ENT_QUOTES, 'UTF-8') ?></td>
                    <td>
                        <span class="rip-badge <?= $entry['status'] === 'published' ? 'rip-badge--sent' : 'rip-badge--pending' ?>">
                            <?= htmlspecialchars($entry['status'], ENT_QUOTES, 'UTF-8') ?>
                        </span>
                    </td>
                    <td style="white-space:nowrap; font-size:var(--rip-font-size-sm); color:var(--rip-gray-500);">
                        <?= htmlspecialchars($entry['published_date'] ?? '', ENT_QUOTES, 'UTF-8') ?>
                    </td>
                    <td style="white-space:nowrap;">
                        <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/content/edit/<?= (int) $entry['id'] ?>" class="rip-link" style="margin-right:8px;">Edit</a>
                        <form method="post" action="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/content/delete/<?= (int) $entry['id'] ?>" style="display:inline;" onsubmit="return confirm('Delete this content?');">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8') ?>">
                            <button type="submit" class="rip-button rip-button--danger">Delete</button>
                        </form>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<?php if ($total_pages > 1): ?>
<div class="rip-pagination">
    <?php if ($page > 1): ?>
        <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/content?page=<?= $page - 1 ?>">&laquo;</a>
    <?php endif; ?>
    <?php for ($i = 1; $i <= $total_pages; $i++): ?>
        <?php if ($i === $page): ?>
            <span class="current"><?= $i ?></span>
        <?php else: ?>
            <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/content?page=<?= $i ?>"><?= $i ?></a>
        <?php endif; ?>
    <?php endfor; ?>
    <?php if ($page < $total_pages): ?>
        <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/content?page=<?= $page + 1 ?>">&raquo;</a>
    <?php endif; ?>
</div>
<?php endif; ?>
<?php endif; ?>

<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
?>
