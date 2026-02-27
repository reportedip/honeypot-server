<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Trap;

use ReportedIp\Honeypot\Persistence\Database;

/**
 * Interface for traps that require database access.
 */
interface DatabaseAwareInterface
{
    public function setDatabase(Database $db): void;
}
