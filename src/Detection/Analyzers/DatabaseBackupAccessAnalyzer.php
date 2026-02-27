<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Detection\Analyzers;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Detection\AnalyzerInterface;
use ReportedIp\Honeypot\Detection\DetectionResult;

/**
 * Detects attempts to access database backup and dump files.
 *
 * Checks for SQL dump files, common backup paths, well-known backup filenames,
 * database-related archive files, and phpMyAdmin export patterns in the request path.
 */
final class DatabaseBackupAccessAnalyzer implements AnalyzerInterface
{
    /** Database backup file extensions. */
    private const BACKUP_EXTENSIONS = [
        '.sql',
        '.sql.gz',
        '.sql.bz2',
        '.sql.zip',
        '.dump',
        '.dump.gz',
    ];

    /** Common backup directory path segments. */
    private const BACKUP_PATHS = [
        '/backup/',
        '/backups/',
        '/db/',
        '/database/',
        '/data/',
    ];

    /** Specific well-known backup filenames. */
    private const BACKUP_FILENAMES = [
        'backup.sql',
        'database.sql',
        'dump.sql',
        'db.sql',
        'wordpress.sql',
        'wp.sql',
        'site.sql',
        'mysql.sql',
    ];

    /** Archive extensions that may contain database dumps. */
    private const ARCHIVE_EXTENSIONS = [
        '.tar.gz',
        '.tar.bz2',
        '.zip',
        '.rar',
        '.7z',
    ];

    /** Database-related name segments for archive detection. */
    private const DB_NAME_SEGMENTS = [
        'backup',
        'database',
        'dump',
        'mysql',
        'db',
        'sql',
        'data',
    ];

    public function getName(): string
    {
        return 'DatabaseBackupAccess';
    }

    public function analyze(Request $request): ?DetectionResult
    {
        $path = strtolower($request->getPath());
        $uri = strtolower($request->getUri());

        if ($path === '' || $path === '/') {
            return null;
        }

        $findings = [];
        $maxScore = 0;

        // Check for backup database file extensions
        foreach (self::BACKUP_EXTENSIONS as $ext) {
            if (str_ends_with($path, $ext)) {
                $findings[] = sprintf('Database backup file extension: %s', $ext);
                $maxScore = max($maxScore, 75);
            }
        }

        // Check for common backup directory paths
        foreach (self::BACKUP_PATHS as $backupPath) {
            if (str_contains($path, $backupPath)) {
                $findings[] = sprintf('Backup directory access: %s', $backupPath);
                $maxScore = max($maxScore, 65);
            }
        }

        // Check for specific well-known backup filenames
        foreach (self::BACKUP_FILENAMES as $filename) {
            if (str_contains($path, $filename)) {
                $findings[] = sprintf('Known backup filename: %s', $filename);
                $maxScore = max($maxScore, 80);
            }
        }

        // Check for archive files with database-related names
        foreach (self::ARCHIVE_EXTENSIONS as $archiveExt) {
            if (str_ends_with($path, $archiveExt)) {
                foreach (self::DB_NAME_SEGMENTS as $segment) {
                    if (str_contains($path, $segment)) {
                        $findings[] = sprintf('Database archive file: %s with %s', $archiveExt, $segment);
                        $maxScore = max($maxScore, 75);
                        break;
                    }
                }
            }
        }

        // Check for phpMyAdmin export patterns
        if (preg_match('/phpmyadmin.*export/i', $uri) || preg_match('/pma.*export/i', $uri)) {
            $findings[] = 'phpMyAdmin export path detected';
            $maxScore = max($maxScore, 85);
        }

        // Check for phpMyAdmin SQL file patterns
        if (preg_match('/phpmyadmin.*\.sql/i', $uri) || preg_match('/pma.*\.sql/i', $uri)) {
            $findings[] = 'phpMyAdmin SQL file access';
            $maxScore = max($maxScore, 80);
        }

        // Check for common database dump path patterns
        if (preg_match('/\/(db|database|sql)[_\-]?(backup|dump|export)/i', $path)) {
            $findings[] = 'Database dump path pattern detected';
            $maxScore = max($maxScore, 75);
        }

        if (empty($findings)) {
            return null;
        }

        $comment = sprintf(
            'Database backup access attempt: %s (path: %s)',
            implode('; ', array_slice(array_unique($findings), 0, 3)),
            substr($request->getPath(), 0, 200)
        );

        return new DetectionResult([58, 15], $comment, $maxScore, $this->getName());
    }
}
