<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Profile\CmsProfile;
use ReportedIp\Honeypot\Profile\DrupalProfile;
use ReportedIp\Honeypot\Profile\JoomlaProfile;
use ReportedIp\Honeypot\Profile\WordPressProfile;
use ReportedIp\Honeypot\Tests\TestCase;

/**
 * Guards the CMS display names shown in the admin panel.
 *
 * The profile identifier is lowercase ('wordpress'), and `ucfirst()` on it
 * yields "Wordpress" — a misspelling of the trademark. Every user-facing
 * label must therefore go through CmsProfile::displayName().
 */
final class CmsProfileTest extends TestCase
{
    public function testWordPressKeepsItsCapitalP(): void
    {
        $this->t->assertEquals('WordPress', CmsProfile::displayName('wordpress'));
    }

    public function testDrupalAndJoomlaAreCapitalised(): void
    {
        $this->t->assertEquals('Drupal', CmsProfile::displayName('drupal'));
        $this->t->assertEquals('Joomla', CmsProfile::displayName('joomla'));
    }

    public function testMixedCaseAndPaddedInputStillResolve(): void
    {
        $this->t->assertEquals('WordPress', CmsProfile::displayName('WordPress'));
        $this->t->assertEquals('WordPress', CmsProfile::displayName('WORDPRESS'));
        $this->t->assertEquals('WordPress', CmsProfile::displayName(' wordpress '));
    }

    public function testUnknownProfileFallsBackToUcfirst(): void
    {
        $this->t->assertEquals('Typo3', CmsProfile::displayName('typo3'));
        $this->t->assertEquals('', CmsProfile::displayName(''));
    }

    /**
     * Every shipped profile must have an explicit display name — a new profile
     * whose identifier only gets ucfirst()'d is exactly how "Wordpress" got out.
     */
    public function testEveryShippedProfileHasAnExplicitDisplayName(): void
    {
        $expected = [
            WordPressProfile::class => 'WordPress',
            DrupalProfile::class    => 'Drupal',
            JoomlaProfile::class    => 'Joomla',
        ];

        foreach ($expected as $class => $label) {
            $profile = new $class();
            $this->t->assertEquals($label, CmsProfile::displayName($profile->getName()));
        }
    }
}
