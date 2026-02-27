<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;

/**
 * Detects WP-CLI abuse and admin-ajax.php exploitation.
 *
 * Checks for suspicious admin-ajax actions (revslider, duplicator, upload-attachment),
 * shell/exec/eval keywords in action parameters, WP-CLI command patterns in POST body,
 * base64-encoded content in admin-ajax data, and PHP serialized object injection.
 */
final class WpCliAbuseAnalyzer implements AnalyzerInterface
{
    /** Known dangerous admin-ajax action names. */
    private const DANGEROUS_ACTIONS = [
        'revslider_show_image',
        'revslider_ajax_action',
        'duplicator_download',
        'duplicator_package_build',
        'upload-attachment',
        'upload_attachment',
        'editeditor',
        'wp_ajax_upload_file',
        'elementor_upload',
        'wooco_save_option',
        'formcraft3_save_form_progress',
    ];

    /** Shell/exec/eval keywords that are dangerous in action parameters. */
    private const SHELL_KEYWORDS = [
        'shell',
        'exec',
        'eval',
        'system',
        'passthru',
        'popen',
        'proc_open',
        'pcntl_exec',
        'cmd',
        'command',
    ];

    /** WP-CLI command prefixes. */
    private const WP_CLI_COMMANDS = [
        'wp core',
        'wp plugin',
        'wp theme',
        'wp user',
        'wp db',
        'wp config',
        'wp option',
        'wp cron',
        'wp eval',
        'wp shell',
    ];

    public function getName(): string
    {
        return 'WpCliAbuse';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        if (!$request->isPost()) {
            return null;
        }

        $path = strtolower($request->getPath());
        $body = $request->getBody();
        $postData = $request->getPostData();

        // Only trigger on admin-ajax.php or wp-admin POST requests
        $isAdminAjax = str_contains($path, 'admin-ajax.php');
        $isWpAdmin = str_contains($path, '/wp-admin/');

        if (!$isAdminAjax && !$isWpAdmin) {
            return null;
        }

        $findings = [];
        $maxScore = 0;

        // Get the action parameter
        $action = '';
        if (isset($postData['action']) && is_string($postData['action'])) {
            $action = $postData['action'];
        }

        if ($isAdminAjax) {
            // Check for nopriv actions (unauthenticated access)
            if (str_starts_with(strtolower($action), 'wp_ajax_nopriv_')) {
                $findings[] = sprintf('Unauthenticated admin-ajax action: %s', $action);
                $maxScore = max($maxScore, 65);
            }

            // Check for known dangerous actions
            $actionLower = strtolower($action);
            foreach (self::DANGEROUS_ACTIONS as $dangerousAction) {
                if ($actionLower === strtolower($dangerousAction)) {
                    $findings[] = sprintf('Dangerous admin-ajax action: %s', $action);
                    $maxScore = max($maxScore, 75);
                    break;
                }
            }

            // Check for shell/exec/eval keywords in action parameter
            foreach (self::SHELL_KEYWORDS as $keyword) {
                if (stripos($action, $keyword) !== false) {
                    $findings[] = sprintf('Shell keyword in action parameter: %s', $keyword);
                    $maxScore = max($maxScore, 80);
                    break;
                }
            }
        }

        // Check for WP-CLI command patterns in POST body
        $bodyLower = strtolower($body);
        foreach (self::WP_CLI_COMMANDS as $cliCommand) {
            if (str_contains($bodyLower, $cliCommand)) {
                $findings[] = sprintf('WP-CLI command pattern in POST body: %s', $cliCommand);
                $maxScore = max($maxScore, 80);
                break;
            }
        }

        // Check for base64-encoded content in POST data
        $allValues = $this->flattenPostData($postData);
        foreach ($allValues as $key => $value) {
            if (is_string($value) && preg_match('/^[A-Za-z0-9+\/]{40,}={0,2}$/', $value)) {
                // Likely base64-encoded data
                $decoded = @base64_decode($value, true);
                if ($decoded !== false && strlen($decoded) > 10) {
                    // Check if decoded content contains suspicious patterns
                    if (preg_match('/\b(eval|exec|system|passthru|shell_exec|base64_decode)\s*\(/i', $decoded)) {
                        $findings[] = sprintf('Base64-encoded code in POST field "%s"', $key);
                        $maxScore = max($maxScore, 85);
                        break;
                    }

                    $findings[] = sprintf('Base64-encoded content in POST field "%s"', $key);
                    $maxScore = max($maxScore, 65);
                    break;
                }
            }
        }

        // Check for PHP serialized objects in POST data (object injection)
        $serializedPatterns = [
            '/O:\d+:"[^"]+"/i',    // Object: O:4:"Test"
            '/a:\d+:\{/i',          // Array: a:2:{
            '/s:\d+:"[^"]*";/i',    // String: s:4:"test";
        ];

        $bodyAndValues = $body . ' ' . implode(' ', array_values($allValues));
        foreach ($serializedPatterns as $pattern) {
            if (preg_match($pattern, $bodyAndValues)) {
                $findings[] = 'PHP serialized object detected (object injection)';
                $maxScore = max($maxScore, 75);
                break;
            }
        }

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'WP-CLI/admin-ajax abuse detected: %s (path: %s)',
            implode('; ', array_slice(array_unique($findings), 0, 3)),
            substr($request->getPath(), 0, 200)
        );

        return new DetectionResult([21, 15], $comment, $maxScore, $this->getName());
    }

    /**
     * Flatten POST data into a single-level key => value array.
     *
     * @param array<string, mixed> $data
     * @return array<string, string>
     */
    private function flattenPostData(array $data, string $prefix = ''): array
    {
        $result = [];
        foreach ($data as $key => $value) {
            $fullKey = $prefix !== '' ? $prefix . '.' . $key : (string) $key;
            if (is_array($value)) {
                $result = array_merge($result, $this->flattenPostData($value, $fullKey));
            } elseif (is_string($value)) {
                $result[$fullKey] = $value;
            }
        }
        return $result;
    }
}
