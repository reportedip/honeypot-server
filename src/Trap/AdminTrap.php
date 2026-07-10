<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Trap;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Core\Response;
use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Persistence\PayloadCapture;
use ReportedIp\Honeypot\Profile\CmsProfile;

/**
 * Fake CMS admin dashboard trap.
 *
 * Shows a convincing admin interface to waste attacker time, or redirects to
 * login if the attacker has not "authenticated". Attackers who slipped in via
 * the sticky-admin path (see {@see LoginTrap}) can try to upload plugins or
 * themes; those payloads are captured for intel and the install always "fails".
 */
class AdminTrap implements TrapInterface, DatabaseAwareInterface
{
    private ?Database $db = null;

    public function getName(): string
    {
        return 'admin';
    }

    public function setDatabase(Database $db): void
    {
        $this->db = $db;
    }

    public function handle(Request $request, Response $response, CmsProfile $profile): Response
    {
        foreach ($profile->getDefaultHeaders() as $name => $value) {
            $response->setHeader($name, $value);
        }

        // Check for a fake auth cookie to decide whether to show admin or redirect
        $cookies = $request->getHeader('Cookie') ?? '';
        $isAuthenticated = str_contains($cookies, 'wordpress_logged_in')
            || str_contains($cookies, 'SESS')
            || str_contains($cookies, 'joomla_user_state');

        if (!$isAuthenticated) {
            // Redirect to login page like the real CMS would
            $loginPath = $profile->getLoginPath();
            $redirectParam = match ($profile->getName()) {
                'wordpress' => '?redirect_to=' . urlencode($request->getPath()),
                'drupal'    => '?destination=' . urlencode(ltrim($request->getPath(), '/')),
                'joomla'    => '?return=' . base64_encode($request->getPath()),
                default     => '',
            };
            $response->redirect($loginPath . $redirectParam, 302);
            return $response;
        }

        // Authenticated (fake) session: capture plugin/theme upload payloads.
        if ($request->isPost() && $this->isUploadRequest($request)) {
            $this->captureUpload($request);
            $response->setStatusCode(200);
            $response->setContentType('text/html; charset=UTF-8');
            $response->setHeader('X-Robots-Tag', 'noindex, nofollow');
            $response->setBody($this->uploadFailurePage($request));
            return $response;
        }

        $data = $profile->getTemplateData();
        $data['request_path'] = $request->getPath();
        $templatePath = __DIR__ . '/../../templates/' . $profile->getTemplatePath() . '/admin.php';

        $response->setStatusCode(200);
        $response->setContentType('text/html; charset=UTF-8');
        $response->setHeader('Cache-Control', 'no-cache, must-revalidate, max-age=0');
        $response->setHeader('X-Robots-Tag', 'noindex, nofollow');
        $response->renderTemplate($templatePath, $data);

        return $response;
    }

    /**
     * Whether the request targets a plugin/theme/media upload endpoint or
     * carries uploaded files.
     */
    private function isUploadRequest(Request $request): bool
    {
        $uri = $request->getUri();

        if (preg_match('#/wp-admin/(update|async-upload|media-new)\.php#i', $uri)
            || preg_match('#action=(upload-plugin|upload-theme|upload-attachment)#i', $uri)
            || preg_match('#/administrator/index\.php\?option=com_installer#i', $uri)) {
            return true;
        }

        // Multipart upload with attached files.
        return isset($_FILES) && is_array($_FILES) && $_FILES !== [];
    }

    /**
     * Persist uploaded file contents (multipart) and the raw body for intel.
     */
    private function captureUpload(Request $request): void
    {
        if ($this->db === null) {
            return;
        }

        $capture = new PayloadCapture($this->db);
        $captured = false;

        if (isset($_FILES) && is_array($_FILES)) {
            foreach ($_FILES as $file) {
                if (!is_array($file) || !isset($file['tmp_name'])) {
                    continue;
                }
                $tmp = (string) $file['tmp_name'];
                if ($tmp === '' || !is_readable($tmp)) {
                    continue;
                }
                $content = (string) @file_get_contents($tmp);
                if ($content === '') {
                    continue;
                }
                $capture->store(
                    $request,
                    'admin_upload',
                    $content,
                    (string) ($file['name'] ?? ''),
                    (string) ($file['type'] ?? '')
                );
                $captured = true;
            }
        }

        // Fall back to the raw body (e.g. base64 / raw-POST uploads).
        $body = $request->getBody();
        if (!$captured && $body !== '') {
            $capture->store($request, 'admin_upload_body', $body, basename($request->getPath()));
        }
    }

    /**
     * A realistic WordPress "install failed" page so the attacker believes the
     * upload was rejected rather than silently swallowed.
     */
    private function uploadFailurePage(Request $request): string
    {
        $isTheme = (bool) preg_match('#upload-theme#i', $request->getUri());
        $what = $isTheme ? 'theme' : 'plugin';

        return <<<HTML
        <!DOCTYPE html>
        <html lang="en-US"><head><meta charset="UTF-8">
        <meta name="viewport" content="width=device-width,initial-scale=1.0">
        <title>Install {$what} &lsaquo; WordPress</title></head>
        <body class="wp-admin wp-core-ui">
        <div class="wrap">
        <h1>Installing {$what} from uploaded file</h1>
        <p>Unpacking the package&hellip;</p>
        <p>Installing the {$what}&hellip;</p>
        <p>The package could not be installed. <strong>Incompatible Archive.</strong></p>
        <p>PCLZIP_ERR_BAD_FORMAT (-10) : Unable to find End of Central Dir Record signature.</p>
        <p>Installation failed.</p>
        </div>
        </body></html>
        HTML;
    }
}
