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
     *
     * @param array<string, mixed> $config Application config to pass to the profile.
     */
    public static function create(string $name, array $config = []): CmsProfile
    {
        $profile = match (strtolower(trim($name))) {
            'wordpress', 'wp' => new WordPressProfile(),
            'drupal'          => new DrupalProfile(),
            'joomla'          => new JoomlaProfile(),
            default           => new WordPressProfile(),
        };

        $profile->setConfig($config);

        return $profile;
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
