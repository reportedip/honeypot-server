<?php
/**
 * Admin Content Generation Template (AJAX-based)
 *
 * Variables: $admin_path, $csrf_token, $cms_profile, $preview, $message, $message_type, $error
 */

$page_title = 'Generate Content';
$active_tab = 'content';

ob_start();
?>

<?php if (!empty($error)): ?>
<div class="rip-alert rip-alert--error"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></div>
<?php endif; ?>

<?php if (empty($preview)): ?>
<!-- Generation Form -->
<div class="rip-card" id="generate-form-card">
    <div class="rip-card__header">Generate AI Content</div>
    <form id="generate-form" onsubmit="return startGeneration(event)">
        <input type="hidden" name="csrf_token" id="csrf-token" value="<?= htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8') ?>">

        <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:16px; margin-bottom:16px;">
            <div class="rip-form-group" style="margin-bottom:0;">
                <label class="rip-label">Topic / Niche</label>
                <input type="text" name="niche" id="gen-niche" placeholder="e.g., digital marketing, web development" class="rip-input">
            </div>
            <div class="rip-form-group" style="margin-bottom:0;">
                <label class="rip-label">Number of Posts</label>
                <input type="number" name="count" id="gen-count" value="3" min="1" max="10" class="rip-input">
            </div>
            <div class="rip-form-group" style="margin-bottom:0;">
                <label class="rip-label">Language</label>
                <select name="language" id="gen-language" class="rip-select">
                    <option value="de">Deutsch</option>
                    <option value="en">English</option>
                </select>
            </div>
        </div>

        <div class="rip-form-group">
            <label class="rip-label">Style Notes (optional)</label>
            <textarea name="style" id="gen-style" rows="2" placeholder="e.g., professional tone, include statistics, focus on practical tips" class="rip-textarea"></textarea>
        </div>

        <div class="rip-help-text" style="margin-bottom:16px;">
            CMS Profile: <strong><?= htmlspecialchars(ucfirst($cms_profile), ENT_QUOTES, 'UTF-8') ?></strong> &mdash;
            Posts are generated one at a time via OpenAI API to avoid timeouts.
        </div>

        <button type="submit" id="gen-submit" class="rip-button rip-button--primary rip-button--lg">Generate</button>
        <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/content" class="rip-button rip-button--ghost" style="margin-left:12px;">Cancel</a>
    </form>
</div>

<!-- Progress (hidden until generation starts) -->
<div id="generate-progress" style="display:none;">
    <div class="rip-card">
        <div class="rip-card__header">
            <span id="progress-title">Generating posts...</span>
            <span style="float:right; font-weight:400; font-size:var(--rip-font-size-sm); color:var(--rip-gray-500);">
                <span id="progress-count">0</span> / <span id="progress-total">0</span>
            </span>
        </div>
        <div style="padding:4px 0;">
            <div style="width:100%; height:8px; background:var(--rip-gray-200); border-radius:var(--rip-radius-full); overflow:hidden;">
                <div id="progress-bar" style="width:0%; height:100%; background:var(--rip-primary); border-radius:var(--rip-radius-full); transition:width 0.4s ease;"></div>
            </div>
        </div>
        <div id="progress-log" style="margin-top:12px; font-size:var(--rip-font-size-sm); color:var(--rip-gray-500); max-height:120px; overflow-y:auto;"></div>
    </div>
</div>

<!-- Generated posts appear here -->
<div id="generated-posts" style="display:none;">
    <div style="margin-bottom:16px; display:flex; justify-content:space-between; align-items:center;">
        <div style="font-size:15px; font-weight:600;"><span id="result-count">0</span> Posts Generated</div>
        <form method="post" action="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/content/save" style="display:inline;">
            <input type="hidden" name="csrf_token" id="save-csrf" value="<?= htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="save_all" value="1">
            <button type="submit" class="rip-button rip-button--success">Save All</button>
        </form>
    </div>
    <div id="posts-container"></div>
    <div style="margin-top:16px;">
        <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/content/generate" class="rip-link" style="font-size:var(--rip-font-size-base);">&larr; Generate more</a>
        &nbsp;&middot;&nbsp;
        <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/content" class="rip-link--muted" style="font-size:var(--rip-font-size-base); text-decoration:none;">Back to content list</a>
    </div>
</div>

<script>
var adminPath = <?= json_encode($admin_path) ?>;
var csrfToken = document.getElementById('csrf-token').value;

var topicVariations = [];
function generateTopicVariations(niche, count) {
    var n = niche || 'general business topics';
    var templates = [
        'Getting started with ' + n,
        'Top tips for ' + n + ' success',
        'Common mistakes in ' + n,
        'The future of ' + n,
        'How to improve your ' + n + ' strategy',
        'A beginner\'s guide to ' + n,
        'Best practices for ' + n,
        'Why ' + n + ' matters for your business',
        n + ' trends you should know',
        'Expert advice on ' + n
    ];
    var topics = [];
    for (var i = 0; i < count; i++) {
        topics.push(templates[i % templates.length]);
    }
    return topics;
}

function startGeneration(e) {
    e.preventDefault();

    var count = Math.max(1, Math.min(10, parseInt(document.getElementById('gen-count').value) || 3));
    var niche = document.getElementById('gen-niche').value.trim();
    var language = document.getElementById('gen-language').value;
    var style = document.getElementById('gen-style').value.trim();

    topicVariations = generateTopicVariations(niche, count);

    // Hide form, show progress
    document.getElementById('generate-form-card').style.display = 'none';
    document.getElementById('generate-progress').style.display = 'block';
    document.getElementById('progress-total').textContent = count;
    document.getElementById('progress-count').textContent = '0';
    document.getElementById('progress-bar').style.width = '0%';
    document.getElementById('progress-log').innerHTML = '';

    // Reset server-side session preview
    fetch(adminPath + '/content/api/reset-preview', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: 'csrf_token=' + encodeURIComponent(csrfToken)
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.csrf_token) csrfToken = data.csrf_token;
        generateNext(0, count, language, style);
    })
    .catch(function() {
        generateNext(0, count, language, style);
    });
}

function generateNext(index, total, language, style) {
    if (index >= total) {
        // All done
        document.getElementById('progress-title').textContent = 'Generation complete!';
        document.getElementById('progress-bar').style.background = 'var(--rip-success)';
        addLogEntry('All ' + total + ' posts generated successfully.', 'success');
        document.getElementById('generated-posts').style.display = 'block';
        document.getElementById('result-count').textContent = document.getElementById('posts-container').children.length;
        document.getElementById('save-csrf').value = csrfToken;
        return;
    }

    var topic = topicVariations[index] || '';
    addLogEntry('Generating post ' + (index + 1) + '/' + total + ': ' + topic + '...', 'info');

    var body = 'csrf_token=' + encodeURIComponent(csrfToken)
        + '&topic=' + encodeURIComponent(topic)
        + '&language=' + encodeURIComponent(language)
        + '&style=' + encodeURIComponent(style);

    fetch(adminPath + '/content/api/generate-one', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: body
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        if (data.csrf_token) csrfToken = data.csrf_token;

        if (data.error) {
            addLogEntry('Error on post ' + (index + 1) + ': ' + data.error, 'error');
        } else if (data.post) {
            addPostCard(data.post, data.index);
            addLogEntry('Post ' + (index + 1) + ' generated: ' + (data.post.title || 'Untitled'), 'success');
        }

        // Update progress
        var done = index + 1;
        document.getElementById('progress-count').textContent = done;
        document.getElementById('progress-bar').style.width = Math.round((done / total) * 100) + '%';

        // Next post
        generateNext(index + 1, total, language, style);
    })
    .catch(function(err) {
        if (err && err.message) {
            addLogEntry('Network error on post ' + (index + 1) + ': ' + err.message, 'error');
        }
        var done = index + 1;
        document.getElementById('progress-count').textContent = done;
        document.getElementById('progress-bar').style.width = Math.round((done / total) * 100) + '%';
        generateNext(index + 1, total, language, style);
    });
}

function addLogEntry(text, type) {
    var log = document.getElementById('progress-log');
    var entry = document.createElement('div');
    entry.style.padding = '2px 0';
    if (type === 'error') entry.style.color = 'var(--rip-danger)';
    else if (type === 'success') entry.style.color = 'var(--rip-success)';
    entry.textContent = text;
    log.appendChild(entry);
    log.scrollTop = log.scrollHeight;
}

function addPostCard(post, sessionIndex) {
    var container = document.getElementById('posts-container');
    var card = document.createElement('div');
    card.className = 'rip-card';
    card.style.marginBottom = '12px';

    var esc = function(s) {
        var d = document.createElement('div');
        d.textContent = s || '';
        return d.innerHTML;
    };

    card.innerHTML = '<div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:10px;">'
        + '<div>'
        + '<h3 style="font-size:var(--rip-font-size-lg); font-weight:600; margin-bottom:4px;">' + esc(post.title) + '</h3>'
        + '<div style="font-size:var(--rip-font-size-sm); color:var(--rip-gray-500);">'
        + 'By ' + esc(post.author) + ' &middot; ' + esc(post.category) + ' &middot; ' + esc(post.published_date)
        + '</div></div>'
        + '<form method="post" action="' + esc(adminPath) + '/content/save" style="display:inline;">'
        + '<input type="hidden" name="csrf_token" value="' + esc(csrfToken) + '">'
        + '<input type="hidden" name="save_indices[]" value="' + sessionIndex + '">'
        + '<button type="submit" class="rip-button rip-button--success rip-button--sm">Save</button>'
        + '</form></div>'
        + '<div style="font-size:var(--rip-font-size-base); color:var(--rip-gray-600); padding:8px 12px; background:var(--rip-bg-code); border-radius:var(--rip-radius-md); margin-bottom:8px;">'
        + esc(post.excerpt) + '</div>'
        + '<div style="font-size:var(--rip-font-size-xs); color:var(--rip-gray-400); font-family:var(--rip-font-mono);">'
        + 'Slug: ' + esc(post.slug) + ' &middot; Meta: ' + esc(post.meta_description)
        + '</div>';

    container.appendChild(card);
}
</script>

<?php else: ?>
<!-- Preview Generated Content (fallback for session-stored previews) -->
<div style="margin-bottom:16px; display:flex; justify-content:space-between; align-items:center;">
    <div style="font-size:15px; font-weight:600;"><?= count($preview) ?> Posts Generated</div>
    <form method="post" action="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/content/save" style="display:inline;">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8') ?>">
        <input type="hidden" name="save_all" value="1">
        <button type="submit" class="rip-button rip-button--success">Save All</button>
    </form>
</div>

<?php foreach ($preview as $i => $item): ?>
<div class="rip-card">
    <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:10px;">
        <div>
            <h3 style="font-size:var(--rip-font-size-lg); font-weight:600; margin-bottom:4px;"><?= htmlspecialchars($item['title'] ?? '', ENT_QUOTES, 'UTF-8') ?></h3>
            <div style="font-size:var(--rip-font-size-sm); color:var(--rip-gray-500);">
                By <?= htmlspecialchars($item['author'] ?? 'admin', ENT_QUOTES, 'UTF-8') ?>
                &middot; <?= htmlspecialchars($item['category'] ?? '', ENT_QUOTES, 'UTF-8') ?>
                &middot; <?= htmlspecialchars($item['published_date'] ?? '', ENT_QUOTES, 'UTF-8') ?>
            </div>
        </div>
        <form method="post" action="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/content/save" style="display:inline;">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8') ?>">
            <input type="hidden" name="save_indices[]" value="<?= $i ?>">
            <button type="submit" class="rip-button rip-button--success rip-button--sm">Save</button>
        </form>
    </div>
    <div style="font-size:var(--rip-font-size-base); color:var(--rip-gray-600); padding:8px 12px; background:var(--rip-bg-code); border-radius:var(--rip-radius-md); margin-bottom:8px;">
        <?= htmlspecialchars($item['excerpt'] ?? '', ENT_QUOTES, 'UTF-8') ?>
    </div>
    <div style="font-size:var(--rip-font-size-xs); color:var(--rip-gray-400); font-family:var(--rip-font-mono);">
        Slug: <?= htmlspecialchars($item['slug'] ?? '', ENT_QUOTES, 'UTF-8') ?>
        &middot; Meta: <?= htmlspecialchars($item['meta_description'] ?? '', ENT_QUOTES, 'UTF-8') ?>
    </div>
</div>
<?php endforeach; ?>

<div style="margin-top:16px;">
    <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/content/generate" class="rip-link" style="font-size:var(--rip-font-size-base);">&larr; Generate more</a>
    &nbsp;&middot;&nbsp;
    <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/content" class="rip-link--muted" style="font-size:var(--rip-font-size-base); text-decoration:none;">Back to content list</a>
</div>

<?php endif; ?>

<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
?>
