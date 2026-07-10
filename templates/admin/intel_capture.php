<?php
/**
 * Admin Captured-Payload Detail Template
 *
 * Variables: $capture, $admin_path, $csrf_token
 *
 * The payload is attacker-controlled and potentially hostile, so it is only
 * ever shown as escaped text inside a <pre> — never rendered as active markup.
 */

$page_title = 'Captured Payload';
$active_tab = 'intel';

$base = htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8');
$raw = (string) ($capture['content'] ?? '');

// Build a printable preview: escape, and replace control bytes with a dot so
// binary uploads (ZIP, etc.) render harmlessly instead of corrupting the page.
$previewRaw = substr($raw, 0, 20000);
$printable = preg_replace('/[^\P{C}\t\r\n]/u', '.', $previewRaw);
if ($printable === null) {
    // Not valid UTF-8 (true binary): fall back to a byte-safe replacement.
    $printable = preg_replace('/[^\x09\x0A\x0D\x20-\x7E]/', '.', $previewRaw);
}
$truncated = strlen($raw) > 20000;

ob_start();
?>

<div style="margin-bottom:16px;">
    <a href="<?= $base ?>/intel?tab=captures" class="rip-link">&laquo; Back to captures</a>
</div>

<div class="rip-card">
    <div class="rip-card__header">Payload Metadata</div>
    <table class="rip-table rip-table--compact">
        <tbody>
            <tr><th style="width:160px;">Source IP</th><td style="font-family:var(--rip-font-mono);"><?= htmlspecialchars((string) $capture['ip'], ENT_QUOTES, 'UTF-8') ?></td></tr>
            <tr><th>Capture type</th><td><span class="rip-badge rip-badge--cat"><?= htmlspecialchars(str_replace('_', ' ', (string) $capture['capture_type']), ENT_QUOTES, 'UTF-8') ?></span></td></tr>
            <tr><th>Filename</th><td><?= htmlspecialchars((string) ($capture['filename'] ?? ''), ENT_QUOTES, 'UTF-8') ?: '—' ?></td></tr>
            <tr><th>Declared type</th><td><?= htmlspecialchars((string) ($capture['content_type'] ?? ''), ENT_QUOTES, 'UTF-8') ?: '—' ?></td></tr>
            <tr><th>Size</th><td><?= number_format((int) $capture['size']) ?> bytes</td></tr>
            <tr><th>Request URI</th><td style="font-family:var(--rip-font-mono); font-size:var(--rip-font-size-sm); word-break:break-all;"><?= htmlspecialchars((string) $capture['request_uri'], ENT_QUOTES, 'UTF-8') ?></td></tr>
            <tr><th>User-Agent</th><td style="font-size:var(--rip-font-size-sm); word-break:break-all;"><?= htmlspecialchars((string) $capture['user_agent'], ENT_QUOTES, 'UTF-8') ?></td></tr>
            <tr><th>Captured at</th><td><?= htmlspecialchars((string) $capture['timestamp'], ENT_QUOTES, 'UTF-8') ?></td></tr>
        </tbody>
    </table>
    <div style="margin-top:16px;">
        <a href="<?= $base ?>/intel/capture/<?= (int) $capture['id'] ?>/download" class="rip-button rip-button--secondary rip-button--sm">Download raw</a>
    </div>
</div>

<div class="rip-card">
    <div class="rip-card__header">
        Payload Preview
        <?php if ($truncated): ?>
            <span style="float:right; font-size:var(--rip-font-size-sm); font-weight:400; color:var(--rip-gray-500);">first 20 KB shown &mdash; download for full payload</span>
        <?php endif; ?>
    </div>
    <pre style="background:var(--rip-bg-code); padding:14px; overflow-x:auto; font-family:var(--rip-font-mono); font-size:var(--rip-font-size-sm); line-height:1.5; white-space:pre-wrap; word-break:break-all; max-height:520px;"><?= htmlspecialchars($printable, ENT_QUOTES, 'UTF-8') ?></pre>
</div>

<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
?>
