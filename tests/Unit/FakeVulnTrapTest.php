<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Core\Response;
use ReportedIp\Honeypot\Profile\WordPressProfile;
use ReportedIp\Honeypot\Tests\TestCase;
use ReportedIp\Honeypot\Trap\FakeVulnTrap;

/**
 * The fake directory listing must not feed a crawler that appends its sort
 * links to the URL it already has.
 */
final class FakeVulnTrapTest extends TestCase
{
    public function testListingIsServedForOneSortParameter(): void
    {
        $request = $this->createRequest(['uri' => '/wp-content/uploads/?C=N;O=D']);
        $response = (new FakeVulnTrap())->handle($request, new Response(), new WordPressProfile());
        $this->t->assertEquals(200, $response->getStatusCode());
        $this->t->assertTrue(str_contains($response->getBody(), 'Index of /wp-content/uploads/'), 'listing expected');
    }

    public function testAppendedSortLinkEndsTheLoop(): void
    {
        $request = $this->createRequest(['uri' => '/wp-content/uploads/?C=N;O=D?C=N;O=D']);
        $response = (new FakeVulnTrap())->handle($request, new Response(), new WordPressProfile());
        $this->t->assertEquals(404, $response->getStatusCode());
        $this->t->assertFalse(str_contains($response->getBody(), 'Index of'), 'no listing for a looping URL');
    }
}
