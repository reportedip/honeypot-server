<?php
/**
 * Admin Content Edit Template
 *
 * Variables: $admin_path, $csrf_token, $entry
 */

$page_title = 'Edit Content';
$active_tab = 'content';

ob_start();
?>

<div class="rip-card">
    <div class="rip-card__header">Edit Content #<?= (int) $entry['id'] ?></div>
    <form method="post" action="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/content/edit/<?= (int) $entry['id'] ?>">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8') ?>">

        <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:16px;">
            <div class="rip-form-group" style="margin-bottom:0;">
                <label class="rip-label">Title</label>
                <input type="text" name="title" value="<?= htmlspecialchars($entry['title'] ?? '', ENT_QUOTES, 'UTF-8') ?>" required class="rip-input">
            </div>
            <div class="rip-form-group" style="margin-bottom:0;">
                <label class="rip-label">Slug</label>
                <input type="text" name="slug" value="<?= htmlspecialchars($entry['slug'] ?? '', ENT_QUOTES, 'UTF-8') ?>" required class="rip-input">
            </div>
        </div>

        <div class="rip-form-group">
            <label class="rip-label">Content (HTML)</label>
            <textarea name="content" rows="12" class="rip-textarea" style="font-family:var(--rip-font-mono);"><?= htmlspecialchars($entry['content'] ?? '', ENT_QUOTES, 'UTF-8') ?></textarea>
        </div>

        <div class="rip-form-group">
            <label class="rip-label">Excerpt</label>
            <textarea name="excerpt" rows="2" class="rip-textarea"><?= htmlspecialchars($entry['excerpt'] ?? '', ENT_QUOTES, 'UTF-8') ?></textarea>
        </div>

        <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:16px; margin-bottom:16px;">
            <div class="rip-form-group" style="margin-bottom:0;">
                <label class="rip-label">Author</label>
                <input type="text" name="author" value="<?= htmlspecialchars($entry['author'] ?? 'admin', ENT_QUOTES, 'UTF-8') ?>" class="rip-input">
            </div>
            <div class="rip-form-group" style="margin-bottom:0;">
                <label class="rip-label">Category</label>
                <input type="text" name="category" value="<?= htmlspecialchars($entry['category'] ?? 'Uncategorized', ENT_QUOTES, 'UTF-8') ?>" class="rip-input">
            </div>
            <div class="rip-form-group" style="margin-bottom:0;">
                <label class="rip-label">Status</label>
                <select name="status" class="rip-select">
                    <option value="published" <?= ($entry['status'] ?? '') === 'published' ? 'selected' : '' ?>>Published</option>
                    <option value="draft" <?= ($entry['status'] ?? '') === 'draft' ? 'selected' : '' ?>>Draft</option>
                </select>
            </div>
        </div>

        <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:16px;">
            <div class="rip-form-group" style="margin-bottom:0;">
                <label class="rip-label">Published Date</label>
                <input type="text" name="published_date" value="<?= htmlspecialchars($entry['published_date'] ?? '', ENT_QUOTES, 'UTF-8') ?>" class="rip-input">
            </div>
            <div class="rip-form-group" style="margin-bottom:0;">
                <label class="rip-label">Meta Description</label>
                <input type="text" name="meta_description" value="<?= htmlspecialchars($entry['meta_description'] ?? '', ENT_QUOTES, 'UTF-8') ?>" maxlength="160" class="rip-input">
            </div>
        </div>

        <div style="display:flex; gap:12px;">
            <button type="submit" class="rip-button rip-button--success rip-button--lg">Save Changes</button>
            <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/content" class="rip-button rip-button--secondary rip-button--lg">Cancel</a>
        </div>
    </form>
</div>

<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
?>
