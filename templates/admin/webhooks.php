<?php
/**
 * Admin Webhooks Template — external report targets
 *
 * Variables: $webhooks, $edit_webhook, $all_categories, $all_analyzers,
 *            $admin_path, $csrf_token, $message, $message_type
 */

$page_title = 'Webhooks';
$active_tab = 'webhooks';

$isEdit = isset($edit_webhook) && $edit_webhook !== null;
$formAction = $isEdit
    ? $admin_path . '/webhooks/edit/' . (int) $edit_webhook['id']
    : $admin_path . '/webhooks';

$selectedCategories = $isEdit && trim((string) $edit_webhook['categories']) !== ''
    ? array_map('intval', explode(',', (string) $edit_webhook['categories']))
    : [];
$selectedAnalyzers = $isEdit && trim((string) $edit_webhook['analyzers']) !== ''
    ? array_map('trim', explode(',', (string) $edit_webhook['analyzers']))
    : [];

$currentMethod = $isEdit ? strtoupper((string) ($edit_webhook['method'] ?? 'POST')) : 'POST';
$currentFormat = $isEdit ? (string) ($edit_webhook['body_format'] ?? 'json') : 'json';
$currentHeaders = $isEdit ? (string) ($edit_webhook['headers'] ?? '') : '';
$currentTemplate = $isEdit ? (string) ($edit_webhook['body_template'] ?? '') : '';

ob_start();
?>

<!-- Webhook list -->
<div class="rip-card">
    <div class="rip-card__header">External Report Targets</div>
    <p style="font-size:var(--rip-font-size-base); color:var(--rip-gray-500); margin-bottom:14px;">
        Forward detections to your own logging/SIEM systems or third-party abuse databases
        (e.g. AbuseIPDB) in real time. Body format, HTTP method, and headers are configurable
        per endpoint &mdash; use the presets below for common targets. Leave both filters empty
        to receive all detections; with filters set, the webhook triggers when the category
        <em>or</em> the analyzer matches.
    </p>

    <?php if (empty($webhooks)): ?>
        <div class="rip-empty-state">
            <div class="rip-empty-state__title">No webhooks configured</div>
            <div class="rip-empty-state__text">Add an endpoint below to forward detections to your own systems.</div>
        </div>
    <?php else: ?>
        <table class="rip-table">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>URL</th>
                    <th>Filter</th>
                    <th>Status</th>
                    <th>Last Delivery</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($webhooks as $webhook): ?>
                    <?php
                        $whId = (int) $webhook['id'];
                        $whEnabled = (int) $webhook['enabled'] === 1;
                        $whCategories = trim((string) $webhook['categories']);
                        $whAnalyzers = trim((string) $webhook['analyzers']);
                        $whFailures = (int) $webhook['failure_count'];
                    ?>
                    <tr>
                        <td>
                            <strong><?= htmlspecialchars((string) $webhook['name'], ENT_QUOTES, 'UTF-8') ?></strong><br>
                            <span class="rip-badge rip-badge--method"><?= htmlspecialchars(strtoupper((string) ($webhook['method'] ?? 'POST')), ENT_QUOTES, 'UTF-8') ?> &middot; <?= htmlspecialchars((string) ($webhook['body_format'] ?? 'json'), ENT_QUOTES, 'UTF-8') ?></span>
                        </td>
                        <td style="max-width:260px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="<?= htmlspecialchars((string) $webhook['url'], ENT_QUOTES, 'UTF-8') ?>">
                            <span style="font-family:var(--rip-font-mono); font-size:var(--rip-font-size-sm);"><?= htmlspecialchars((string) $webhook['url'], ENT_QUOTES, 'UTF-8') ?></span>
                        </td>
                        <td>
                            <div class="rip-badge-group">
                                <?php if ($whCategories === '' && $whAnalyzers === ''): ?>
                                    <span class="rip-badge rip-badge--cat">All detections</span>
                                <?php else: ?>
                                    <?php if ($whCategories !== ''): ?>
                                        <span class="rip-badge rip-badge--cat">Categories: <?= htmlspecialchars($whCategories, ENT_QUOTES, 'UTF-8') ?></span>
                                    <?php endif; ?>
                                    <?php if ($whAnalyzers !== ''): ?>
                                        <span class="rip-badge rip-badge--method">Analyzers: <?= htmlspecialchars($whAnalyzers, ENT_QUOTES, 'UTF-8') ?></span>
                                    <?php endif; ?>
                                <?php endif; ?>
                            </div>
                        </td>
                        <td>
                            <?php if ($whEnabled): ?>
                                <span class="rip-badge rip-badge--sent">Enabled</span>
                            <?php else: ?>
                                <span class="rip-badge rip-badge--pending">Disabled</span>
                            <?php endif; ?>
                        </td>
                        <td style="font-size:var(--rip-font-size-sm); color:var(--rip-gray-500);">
                            <?php if (!empty($webhook['last_triggered_at'])): ?>
                                <?= htmlspecialchars((string) $webhook['last_triggered_at'], ENT_QUOTES, 'UTF-8') ?><br>
                                <span style="color:<?= $whFailures > 0 ? 'var(--rip-danger)' : 'var(--rip-success)' ?>;">
                                    <?= htmlspecialchars((string) $webhook['last_status'], ENT_QUOTES, 'UTF-8') ?>
                                    <?= $whFailures > 0 ? ' (' . $whFailures . ' failures)' : '' ?>
                                </span>
                            <?php else: ?>
                                Never triggered
                            <?php endif; ?>
                        </td>
                        <td style="white-space:nowrap;">
                            <form method="post" action="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/webhooks/test/<?= $whId ?>" style="display:inline;">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8') ?>">
                                <button type="submit" class="rip-button rip-button--secondary rip-button--sm">Test</button>
                            </form>
                            <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/webhooks/edit/<?= $whId ?>" class="rip-button rip-button--ghost rip-button--sm">Edit</a>
                            <form method="post" action="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/webhooks/toggle/<?= $whId ?>" style="display:inline;">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8') ?>">
                                <button type="submit" class="rip-button rip-button--ghost rip-button--sm"><?= $whEnabled ? 'Disable' : 'Enable' ?></button>
                            </form>
                            <form method="post" action="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/webhooks/delete/<?= $whId ?>" style="display:inline;">
                                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8') ?>">
                                <button type="submit" class="rip-button rip-button--danger rip-button--sm">Delete</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<!-- Add / Edit form -->
<div class="rip-card">
    <div class="rip-card__header"><?= $isEdit ? 'Edit Webhook' : 'Add Webhook' ?></div>
    <form method="post" action="<?= htmlspecialchars($formAction, ENT_QUOTES, 'UTF-8') ?>">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8') ?>">

        <div style="display:grid; grid-template-columns: 1fr 2fr; gap:16px;">
            <div class="rip-form-group">
                <label class="rip-label" for="wh-name">Name</label>
                <input type="text" id="wh-name" name="name" class="rip-input" required
                       value="<?= $isEdit ? htmlspecialchars((string) $edit_webhook['name'], ENT_QUOTES, 'UTF-8') : '' ?>"
                       placeholder="e.g. Company SIEM">
            </div>
            <div class="rip-form-group">
                <label class="rip-label" for="wh-url">Endpoint URL</label>
                <input type="text" id="wh-url" name="url" class="rip-input" required
                       value="<?= $isEdit ? htmlspecialchars((string) $edit_webhook['url'], ENT_QUOTES, 'UTF-8') : '' ?>"
                       placeholder="https://logs.example.com/honeypot-webhook">
                <div class="rip-help-text">Placeholders like <span style="font-family:var(--rip-font-mono);">{{ip_url}}</span> are allowed in the URL (useful for GET-style APIs).</div>
            </div>
        </div>

        <div class="rip-form-group">
            <label class="rip-label">Quick Presets</label>
            <div style="display:flex; gap:8px; flex-wrap:wrap;">
                <button type="button" class="rip-button rip-button--secondary rip-button--sm" data-preset="generic">Generic JSON</button>
                <button type="button" class="rip-button rip-button--secondary rip-button--sm" data-preset="abuseipdb">AbuseIPDB</button>
                <button type="button" class="rip-button rip-button--secondary rip-button--sm" data-preset="slack">Slack</button>
                <button type="button" class="rip-button rip-button--secondary rip-button--sm" data-preset="discord">Discord</button>
            </div>
            <div class="rip-help-text">Presets fill in URL, method, headers, and body template — adjust the API key afterwards.</div>
        </div>

        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:16px;">
            <div class="rip-form-group">
                <label class="rip-label" for="wh-method">HTTP Method</label>
                <select id="wh-method" name="method" class="rip-select">
                    <?php foreach (['POST', 'PUT', 'PATCH', 'GET'] as $m): ?>
                        <option value="<?= $m ?>" <?= $currentMethod === $m ? 'selected' : '' ?>><?= $m ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="rip-form-group">
                <label class="rip-label" for="wh-format">Body Format</label>
                <select id="wh-format" name="body_format" class="rip-select">
                    <option value="json" <?= $currentFormat === 'json' ? 'selected' : '' ?>>JSON (full detection payload)</option>
                    <option value="form" <?= $currentFormat === 'form' ? 'selected' : '' ?>>Form (flat key/value fields)</option>
                    <option value="custom" <?= $currentFormat === 'custom' ? 'selected' : '' ?>>Custom (body template with placeholders)</option>
                </select>
            </div>
        </div>

        <div class="rip-form-group">
            <label class="rip-label" for="wh-headers">Custom HTTP Headers (optional, one per line)</label>
            <textarea id="wh-headers" name="headers" class="rip-textarea" rows="3"
                      placeholder="Key: YOUR_API_KEY&#10;Accept: application/json"><?= htmlspecialchars($currentHeaders, ENT_QUOTES, 'UTF-8') ?></textarea>
            <div class="rip-help-text">Format <span style="font-family:var(--rip-font-mono);">Name: Value</span>. Custom headers override the defaults (e.g. Content-Type).</div>
        </div>

        <div class="rip-form-group" id="wh-template-group">
            <label class="rip-label" for="wh-template">Body Template (used with format "Custom")</label>
            <textarea id="wh-template" name="body_template" class="rip-textarea" rows="3"
                      placeholder="ip={{ip_url}}&amp;categories={{abuseipdb_categories}}&amp;comment={{comment_url}}"><?= htmlspecialchars($currentTemplate, ENT_QUOTES, 'UTF-8') ?></textarea>
            <div class="rip-help-text">
                Placeholders: <span style="font-family:var(--rip-font-mono);">{{ip}} {{categories}} {{abuseipdb_categories}} {{comment}} {{severity}} {{analyzers}} {{uri}} {{method}} {{user_agent}} {{host}} {{timestamp}} {{version}} {{event}}</span>
                &mdash; each also as <span style="font-family:var(--rip-font-mono);">{{name_url}}</span> (URL-encoded) and <span style="font-family:var(--rip-font-mono);">{{name_json}}</span> (JSON-escaped).
            </div>
        </div>

        <div class="rip-form-group">
            <label class="rip-label" for="wh-secret">Secret (optional)</label>
            <input type="text" id="wh-secret" name="secret" class="rip-input"
                   value="<?= $isEdit ? htmlspecialchars((string) $edit_webhook['secret'], ENT_QUOTES, 'UTF-8') : '' ?>"
                   placeholder="Shared secret for HMAC signature">
            <div class="rip-help-text">
                When set, each request carries an <span style="font-family:var(--rip-font-mono);">X-ReportedIP-Signature: sha256=&lt;HMAC&gt;</span>
                header computed over the JSON body.
            </div>
        </div>

        <div class="rip-form-group">
            <label class="rip-label">Category Filter (optional &mdash; none selected = all categories)</label>
            <div style="display:grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap:4px; max-height:220px; overflow-y:auto; border:var(--rip-border); border-radius:var(--rip-radius-md); padding:10px;">
                <?php foreach ($all_categories as $catId => $cat): ?>
                    <label style="display:flex; align-items:center; gap:6px; font-size:var(--rip-font-size-sm); color:var(--rip-gray-600); cursor:pointer;">
                        <input type="checkbox" name="categories[]" value="<?= (int) $catId ?>"
                               <?= in_array((int) $catId, $selectedCategories, true) ? 'checked' : '' ?>>
                        <span><?= (int) $catId ?> &middot; <?= htmlspecialchars($cat['name'], ENT_QUOTES, 'UTF-8') ?></span>
                    </label>
                <?php endforeach; ?>
            </div>
        </div>

        <div class="rip-form-group">
            <label class="rip-label">Analyzer Filter (optional &mdash; none selected = all analyzers)</label>
            <div style="display:grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap:4px; max-height:180px; overflow-y:auto; border:var(--rip-border); border-radius:var(--rip-radius-md); padding:10px;">
                <?php foreach ($all_analyzers as $analyzerName): ?>
                    <label style="display:flex; align-items:center; gap:6px; font-size:var(--rip-font-size-sm); color:var(--rip-gray-600); cursor:pointer;">
                        <input type="checkbox" name="analyzers[]" value="<?= htmlspecialchars($analyzerName, ENT_QUOTES, 'UTF-8') ?>"
                               <?= in_array($analyzerName, $selectedAnalyzers, true) ? 'checked' : '' ?>>
                        <span><?= htmlspecialchars($analyzerName, ENT_QUOTES, 'UTF-8') ?></span>
                    </label>
                <?php endforeach; ?>
            </div>
        </div>

        <div style="display:flex; gap:10px;">
            <button type="submit" class="rip-button rip-button--primary"><?= $isEdit ? 'Save Changes' : 'Add Webhook' ?></button>
            <?php if ($isEdit): ?>
                <a href="<?= htmlspecialchars($admin_path, ENT_QUOTES, 'UTF-8') ?>/webhooks" class="rip-button rip-button--secondary">Cancel</a>
            <?php endif; ?>
        </div>
    </form>
</div>

<!-- Payload reference -->
<div class="rip-card">
    <div class="rip-card__header">Payload Format</div>
    <p style="font-size:var(--rip-font-size-base); color:var(--rip-gray-500); margin-bottom:10px;">
        Every delivery carries an <span style="font-family:var(--rip-font-mono);">X-ReportedIP-Event</span> header
        (<span style="font-family:var(--rip-font-mono);">detection</span> or <span style="font-family:var(--rip-font-mono);">test</span>).
        HTTP method, headers, and body depend on the configuration above &mdash; with the default format
        <span style="font-family:var(--rip-font-mono);">JSON</span>, an HTTP POST with
        <span style="font-family:var(--rip-font-mono);">Content-Type: application/json</span> and the following body is sent:
    </p>
    <pre style="background:var(--rip-bg-code); border:var(--rip-border); border-radius:var(--rip-radius-md); padding:14px; font-family:var(--rip-font-mono); font-size:var(--rip-font-size-sm); overflow-x:auto;">{
  "event": "detection",
  "generated_at": "2026-06-12T14:00:00+00:00",
  "honeypot": { "name": "reportedip-honeypot-server", "version": "<?= htmlspecialchars(\ReportedIp\Honeypot\Core\Version::current(), ENT_QUOTES, 'UTF-8') ?>", "host": "example.com", "profile": "wordpress" },
  "request": { "ip": "203.0.113.50", "method": "POST", "uri": "/wp-login.php", "user_agent": "..." },
  "detections": [
    {
      "analyzer": "SqlInjection",
      "categories": [16, 45],
      "category_names": ["SQL Injection", "Code Injection"],
      "comment": "SQL injection attempt detected: ...",
      "severity": 85
    }
  ]
}</pre>
</div>

<script>
(function () {
    var presets = {
        generic: {
            method: 'POST',
            format: 'json',
            headers: '',
            template: '',
            url: ''
        },
        abuseipdb: {
            method: 'POST',
            format: 'custom',
            headers: 'Key: YOUR_ABUSEIPDB_API_KEY\nAccept: application/json',
            template: 'ip={{ip_url}}&categories={{abuseipdb_categories}}&comment={{comment_url}}',
            url: 'https://api.abuseipdb.com/api/v2/report'
        },
        slack: {
            method: 'POST',
            format: 'custom',
            headers: '',
            template: '{"text":"Honeypot detection from {{ip_json}} (severity {{severity}}): {{comment_json}}"}',
            url: 'https://hooks.slack.com/services/YOUR/WEBHOOK/PATH'
        },
        discord: {
            method: 'POST',
            format: 'custom',
            headers: '',
            template: '{"content":"Honeypot detection from {{ip_json}} (severity {{severity}}): {{comment_json}}"}',
            url: 'https://discord.com/api/webhooks/YOUR/WEBHOOK-PATH'
        }
    };

    document.querySelectorAll('[data-preset]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var p = presets[btn.getAttribute('data-preset')];
            if (!p) { return; }
            document.getElementById('wh-method').value = p.method;
            document.getElementById('wh-format').value = p.format;
            document.getElementById('wh-headers').value = p.headers;
            document.getElementById('wh-template').value = p.template;
            var urlField = document.getElementById('wh-url');
            if (p.url !== '') {
                urlField.value = p.url;
            }
        });
    });
})();
</script>

<?php
$content = ob_get_clean();
include __DIR__ . '/layout.php';
?>
