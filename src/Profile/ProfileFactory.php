<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Profile;

/**
 * Factory for creating CMS profile instances.
 */
final class ProfileFactory
{
    /**
     * Create a CMS profile by name.
     *
     * Falls back to WordPress if the name is unrecognised.
     */
    public static function create(string $name): CmsProfile
    {
        return match (strtolower(trim($name))) {
            'wordpress', 'wp' => new WordPressProfile(),
            'drupal'          => new DrupalProfile(),
            'joomla'          => new JoomlaProfile(),
            default           => new WordPressProfile(),
        };
    }

    /**
     * Get the list of all available CMS profile names.
     *
     * @return string[]
     */
    public static function getAvailable(): array
    {
        return ['wordpress', 'drupal', 'joomla'];
    }
}
