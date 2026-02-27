<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Integration;

use ReportedIp\Honeypot\Tests\TestCase;

/**
 * Integration tests for CMS profile routing.
 *
 * These tests verify that different CMS profiles (WordPress, Drupal, Joomla)
 * correctly route requests to the appropriate trap handlers and generate
 * profile-specific responses.
 *
 * Tests to implement:
 * - WordPress profile routes /wp-login.php to LoginTrap
 * - WordPress profile routes /xmlrpc.php to XmlRpcTrap
 * - WordPress profile routes /wp-admin/ to AdminTrap
 * - WordPress profile routes /wp-json/ to RestApiTrap
 * - Drupal profile routes /user/login to LoginTrap
 * - Joomla profile routes /administrator/ to AdminTrap
 * - Profile headers are applied to responses (X-Powered-By, etc.)
 * - Unknown paths are routed to NotFoundTrap
 * - Profile switching via config works correctly
 *
 * Requirements:
 * - Docker environment running
 * - All CMS templates present in templates/ directory
 *
 * To run: php tests/run-tests.php --integration
 */
final class ProfileRoutingTest extends TestCase
{
    public function testWordPressLoginRouting(): void
    {
        $this->t->skip('Integration test: requires Docker environment');
    }

    public function testWordPressAdminRouting(): void
    {
        $this->t->skip('Integration test: requires Docker environment');
    }

    public function testWordPressApiRouting(): void
    {
        $this->t->skip('Integration test: requires Docker environment');
    }

    public function testDrupalLoginRouting(): void
    {
        $this->t->skip('Integration test: requires Docker environment');
    }

    public function testJoomlaAdminRouting(): void
    {
        $this->t->skip('Integration test: requires Docker environment');
    }

    public function testProfileHeadersAreApplied(): void
    {
        $this->t->skip('Integration test: requires Docker environment');
    }

    public function testUnknownPathReturns404(): void
    {
        $this->t->skip('Integration test: requires Docker environment');
    }
}
