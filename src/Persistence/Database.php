<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Persistence;

use PDO;
use PDOStatement;

/**
 * SQLite database connection and schema manager.
 *
 * Provides a thin wrapper around PDO with automatic table initialization
 * and convenience methods for common operations.
 */
final class Database
{
    private ?PDO $pdo = null;

    public function __construct(private readonly string $dbPath) {}

    /**
     * Get or create the PDO connection.
     */
    public function getConnection(): PDO
    {
        if ($this->pdo === null) {
            $dir = dirname($this->dbPath);
            if (!is_dir($dir)) {
                @mkdir($dir, 0775, true);
            }

            $this->pdo = new PDO(
                'sqlite:' . $this->dbPath,
                null,
                null,
                [
                    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES   => false,
                ]
            );

            // Enable WAL mode for better concurrent access
            $this->pdo->exec('PRAGMA journal_mode=WAL');
            $this->pdo->exec('PRAGMA foreign_keys=ON');
        }

        return $this->pdo;
    }

    /**
     * Initialize the database schema (creates tables if they do not exist).
     */
    public function initialize(): void
    {
        $pdo = $this->getConnection();

        $pdo->exec('
            CREATE TABLE IF NOT EXISTS honeypot_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                categories TEXT NOT NULL,
                comment TEXT NOT NULL,
                user_agent TEXT,
                request_uri TEXT,
                request_method TEXT DEFAULT \'GET\',
                post_data TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                sent INTEGER DEFAULT 0
            )
        ');

        $pdo->exec('CREATE INDEX IF NOT EXISTS idx_logs_ip ON honeypot_logs(ip)');
        $pdo->exec('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON honeypot_logs(timestamp)');
        $pdo->exec('CREATE INDEX IF NOT EXISTS idx_logs_sent ON honeypot_logs(sent)');

        $pdo->exec('
            CREATE TABLE IF NOT EXISTS honeypot_whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE,
                description TEXT,
                added_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_active INTEGER DEFAULT 1
            )
        ');

        $pdo->exec('
            CREATE TABLE IF NOT EXISTS honeypot_content (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cms_profile TEXT NOT NULL,
                title TEXT NOT NULL,
                slug TEXT NOT NULL,
                content TEXT NOT NULL,
                excerpt TEXT NOT NULL,
                author TEXT NOT NULL DEFAULT \'admin\',
                category TEXT NOT NULL DEFAULT \'Uncategorized\',
                status TEXT NOT NULL DEFAULT \'published\',
                content_type TEXT NOT NULL DEFAULT \'post\',
                published_date DATETIME NOT NULL,
                meta_description TEXT DEFAULT \'\',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ');
        $pdo->exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_content_profile_slug ON honeypot_content(cms_profile, slug)');
        $pdo->exec('CREATE INDEX IF NOT EXISTS idx_content_status ON honeypot_content(cms_profile, status)');

        $pdo->exec('
            CREATE TABLE IF NOT EXISTS honeypot_visitors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                user_agent TEXT NOT NULL,
                visitor_type TEXT NOT NULL,
                bot_name TEXT DEFAULT \'\',
                request_uri TEXT NOT NULL,
                request_method TEXT DEFAULT \'GET\',
                route_type TEXT DEFAULT \'\',
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ');
        $pdo->exec('CREATE INDEX IF NOT EXISTS idx_visitors_type ON honeypot_visitors(visitor_type)');
        $pdo->exec('CREATE INDEX IF NOT EXISTS idx_visitors_timestamp ON honeypot_visitors(timestamp)');
        $pdo->exec('CREATE INDEX IF NOT EXISTS idx_visitors_ip ON honeypot_visitors(ip)');
    }

    /**
     * Execute a prepared query and return the statement.
     *
     * @param array<int|string, mixed> $params
     */
    public function query(string $sql, array $params = []): PDOStatement
    {
        $stmt = $this->getConnection()->prepare($sql);
        $stmt->execute($params);
        return $stmt;
    }

    /**
     * Insert a row into a table and return the last insert ID.
     *
     * @param array<string, mixed> $data Column => value pairs.
     */
    public function insert(string $table, array $data): int
    {
        // Validate table name: alphanumeric and underscores only
        if (!preg_match('/^[a-zA-Z_][a-zA-Z0-9_]*$/', $table)) {
            throw new \InvalidArgumentException('Invalid table name.');
        }

        // Validate column names: alphanumeric and underscores only
        $columnNames = [];
        foreach (array_keys($data) as $col) {
            if (!preg_match('/^[a-zA-Z_][a-zA-Z0-9_]*$/', $col)) {
                throw new \InvalidArgumentException('Invalid column name.');
            }
            $columnNames[] = $col;
        }

        $columns = implode(', ', $columnNames);
        $placeholders = implode(', ', array_fill(0, count($data), '?'));

        $sql = sprintf('INSERT INTO %s (%s) VALUES (%s)', $table, $columns, $placeholders);
        $stmt = $this->getConnection()->prepare($sql);
        $stmt->execute(array_values($data));

        return (int) $this->getConnection()->lastInsertId();
    }
}
