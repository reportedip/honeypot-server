<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;
use ReportedIp\Honeypot\Detection\PatternLibrary;

/**
 * Detects abuse of WordPress AJAX and admin-post endpoints.
 *
 * Checks for requests to admin-ajax.php without an action parameter,
 * known dangerous AJAX actions, SQL injection in AJAX parameters,
 * action parameter fuzzing, suspicious admin-post.php usage,
 * and non-browser User-Agents hitting AJAX endpoints.
 */
final class AjaxEndpointAbuseAnalyzer implements AnalyzerInterface
{
    /** Known dangerous AJAX actions commonly targeted by attackers. */
    private const DANGEROUS_ACTIONS = [
        'revslider_show_image',
        'revslider_ajax_action',
        'duplicator_download',
        'duplicator_package_build',
        'wp_file_manager_upload',
        'wp_file_manager_get_file',
        'wp_file_manager_rename',
        'wp_file_manager_delete',
        'wp_file_manager_copy',
        'wp_file_manager_move',
        'upload-attachment',
        'editpost',
        'delete-post',
        'delete-page',
        'trash-post',
        'inline-save',
        'upload-plugin',
        'upload-theme',
        'install-plugin',
        'install-theme',
        'update-plugin',
        'update-theme',
        'edit-theme-plugin-file',
        'wp-remove-post-lock',
        'wp_ajax_crop_image',
        'wp_ajax_save_attachment',
    ];

    /** Max allowed length for an AJAX action name. */
    private const MAX_ACTION_LENGTH = 100;

    public function getName(): string
    {
        return 'AjaxEndpointAbuse';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $findings = [];
        $maxScore = 0;

        $path = $request->getPath();
        $isAjaxEndpoint = (bool) preg_match('/\/wp-admin\/admin-ajax\.php/i', $path);
        $isAdminPostEndpoint = (bool) preg_match('/\/wp-admin\/admin-post\.php/i', $path);

        if (!$isAjaxEndpoint && !$isAdminPostEndpoint) {
            return null;
        }

        // Determine the action from query params or POST data
        $action = $request->getQueryParam('action');
        if ($action === null || $action === '') {
            $postData = $request->getPostData();
            $action = isset($postData['action']) && is_string($postData['action'])
                ? $postData['action']
                : null;
        }

        if ($isAjaxEndpoint) {
            // No action parameter at all is suspicious
            if ($action === null || $action === '') {
                $findings[] = 'AJAX endpoint accessed without action parameter';
                $maxScore = max($maxScore, 50);
            } else {
                // Check for known dangerous AJAX actions
                $actionLower = strtolower($action);
                foreach (self::DANGEROUS_ACTIONS as $dangerous) {
                    if ($actionLower === strtolower($dangerous)) {
                        $findings[] = sprintf('Dangerous AJAX action requested: %s', $action);
                        $maxScore = max($maxScore, 75);
                        break;
                    }
                }

                // Check for wp_file_manager wildcard pattern
                if (preg_match('/^wp_file_manager/i', $action)) {
                    $findings[] = sprintf('WP File Manager AJAX action: %s', $action);
                    $maxScore = max($maxScore, 75);
                }

                // Check for action parameter fuzzing (very long action names)
                if (mb_strlen($action) > self::MAX_ACTION_LENGTH) {
                    $findings[] = sprintf(
                        'AJAX action parameter fuzzing detected (%d chars)',
                        mb_strlen($action)
                    );
                    $maxScore = max($maxScore, 60);
                }

                // Check for SQL injection in AJAX parameters
                $this->checkSqlInjectionInParams($request, $findings, $maxScore);
            }

            // Non-browser User-Agent accessing AJAX endpoints
            if ($this->isNonBrowserUserAgent($request->getUserAgent())) {
                $findings[] = sprintf(
                    'Non-browser User-Agent accessing AJAX endpoint: %s',
                    substr($request->getUserAgent(), 0, 80)
                );
                $maxScore = max($maxScore, 55);
            }
        }

        if ($isAdminPostEndpoint) {
            $findings[] = 'POST to wp-admin/admin-post.php endpoint';
            $maxScore = max($maxScore, 55);

            // Check POST data for suspicious content
            $postData = $request->getPostData();
            $body = $request->getBody();

            if (!empty($postData) || $body !== '') {
                $allValues = $body;
                foreach ($postData as $val) {
                    $allValues .= ' ' . (is_string($val) ? $val : (string) $val);
                }

                $sqlPatterns = PatternLibrary::sqlInjectionPatterns();
                foreach ($sqlPatterns as $pattern) {
                    if (preg_match($pattern, $allValues)) {
                        $findings[] = 'SQL injection payload in admin-post.php data';
                        $maxScore = max($maxScore, 80);
                        break;
                    }
                }
            }

            if ($this->isNonBrowserUserAgent($request->getUserAgent())) {
                $findings[] = 'Non-browser User-Agent accessing admin-post.php';
                $maxScore = max($maxScore, 55);
            }
        }

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'AJAX/admin endpoint abuse detected: %s',
            implode('; ', array_slice($findings, 0, 3))
        );

        return new DetectionResult([21, 15], $comment, $maxScore, $this->getName());
    }

    /**
     * Check all request parameters for SQL injection patterns.
     *
     * @param string[] $findings
     */
    private function checkSqlInjectionInParams(Request $request, array &$findings, int &$maxScore): void
    {
        $params = array_merge($request->getQueryParams(), $request->getPostData());
        $sqlPatterns = PatternLibrary::sqlInjectionPatterns();

        foreach ($params as $key => $val) {
            if ($key === 'action') {
                continue;
            }

            $value = is_string($val) ? $val : (string) $val;
            if ($value === '' || mb_strlen($value) < 4) {
                continue;
            }

            $decoded = urldecode($value);

            foreach ($sqlPatterns as $pattern) {
                if (preg_match($pattern, $value) || preg_match($pattern, $decoded)) {
                    $findings[] = sprintf('SQL injection in AJAX parameter "%s"', $key);
                    $maxScore = max($maxScore, 80);
                    return;
                }
            }
        }
    }

    /**
     * Determine if the User-Agent looks like a non-browser client.
     */
    private function isNonBrowserUserAgent(string $ua): bool
    {
        if ($ua === '') {
            return true;
        }

        // Common browser indicators
        $browserIndicators = [
            'Mozilla/',
            'Chrome/',
            'Safari/',
            'Firefox/',
            'Edge/',
            'Opera/',
            'MSIE ',
            'Trident/',
        ];

        foreach ($browserIndicators as $indicator) {
            if (stripos($ua, $indicator) !== false) {
                return false;
            }
        }

        return true;
    }
}
