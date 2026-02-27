<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;

/**
 * Detects media library abuse and upload directory scanning.
 *
 * Checks for upload directory listing attempts, PHP files in upload directories
 * (webshell indicator), media upload endpoint abuse, year/month directory enumeration,
 * WordPress REST API media access, and Drupal file directory scanning.
 */
final class MediaLibraryAbuseAnalyzer implements AnalyzerInterface
{
    public function getName(): string
    {
        return 'MediaLibraryAbuse';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $path = $request->getPath();
        $pathLower = strtolower($path);

        if ($pathLower === '' || $pathLower === '/') {
            return null;
        }

        $findings = [];
        $maxScore = 0;

        // Direct access to /wp-content/uploads/ directory listing
        if (preg_match('/\/wp-content\/uploads\/?$/i', $pathLower)) {
            $findings[] = 'Upload directory listing attempt: /wp-content/uploads/';
            $maxScore = max($maxScore, 55);
        }

        // Access to PHP files under /wp-content/uploads/ (webshell indicator)
        if (preg_match('/\/wp-content\/uploads\/.*\.php/i', $pathLower)) {
            $findings[] = 'PHP file access in upload directory (webshell indicator)';
            $maxScore = max($maxScore, 70);
        }

        // POST to media upload endpoints
        if ($request->isPost()) {
            if (preg_match('/\/wp-admin\/async-upload\.php/i', $pathLower)) {
                $findings[] = 'POST to async-upload.php (media upload endpoint)';
                $maxScore = max($maxScore, 65);
            }

            if (preg_match('/\/wp-admin\/media-upload\.php/i', $pathLower)) {
                $findings[] = 'POST to media-upload.php';
                $maxScore = max($maxScore, 60);
            }

            if (preg_match('/\/wp-admin\/upload\.php/i', $pathLower)) {
                $findings[] = 'POST to upload.php';
                $maxScore = max($maxScore, 55);
            }
        }

        // Enumeration of upload directories by year/month
        if (preg_match('/\/wp-content\/uploads\/\d{4}\/\d{1,2}\/?$/i', $pathLower)) {
            $findings[] = 'Upload directory enumeration by year/month';
            $maxScore = max($maxScore, 50);
        }

        // Broader year-only enumeration
        if (preg_match('/\/wp-content\/uploads\/\d{4}\/?$/i', $pathLower)) {
            $findings[] = 'Upload directory enumeration by year';
            $maxScore = max($maxScore, 45);
        }

        // WordPress REST API media access
        if (preg_match('/\/wp-json\/wp\/v2\/media/i', $pathLower)) {
            $findings[] = 'WordPress REST API media endpoint access';
            $maxScore = max($maxScore, 55);
        }

        // Drupal: /sites/default/files/ scanning
        if (preg_match('/\/sites\/default\/files\/?/i', $pathLower)) {
            $findings[] = 'Drupal file directory scanning: /sites/default/files/';
            $maxScore = max($maxScore, 55);

            // PHP file under Drupal files directory
            if (preg_match('/\/sites\/default\/files\/.*\.php/i', $pathLower)) {
                $findings[] = 'PHP file access in Drupal files directory (webshell indicator)';
                $maxScore = max($maxScore, 70);
            }
        }

        // Drupal: private files directory
        if (preg_match('/\/system\/files\//i', $pathLower)) {
            $findings[] = 'Drupal private file system access attempt';
            $maxScore = max($maxScore, 50);
        }

        // Joomla: media/images directory scanning
        if (preg_match('/\/images\/stories\//i', $pathLower) || preg_match('/\/media\/com_/i', $pathLower)) {
            if (str_ends_with($pathLower, '.php')) {
                $findings[] = 'PHP file in Joomla media directory (webshell indicator)';
                $maxScore = max($maxScore, 70);
            }
        }

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'Media library abuse detected: %s (path: %s)',
            implode('; ', array_slice(array_unique($findings), 0, 3)),
            substr($request->getPath(), 0, 200)
        );

        return new DetectionResult([52, 21], $comment, $maxScore, $this->getName());
    }
}
