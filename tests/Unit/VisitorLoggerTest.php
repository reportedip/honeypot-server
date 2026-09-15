<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Persistence\Database;
use ReportedIp\Honeypot\Persistence\VisitorLogger;
use ReportedIp\Honeypot\Tests\TestCase;

/**
 * Covers the visitor-type labels and the clickable summary-card filter URLs.
 */
final class VisitorLoggerTest extends TestCase
{
    private const ADMIN = '/_hp_admin';

    public function testTypeLabelsAreSpelledOut(): void
    {
        $this->t->assertEquals('Good Bot', VisitorLogger::typeLabel('good_bot'));
        $this->t->assertEquals('AI Agent', VisitorLogger::typeLabel('ai_agent'));
        $this->t->assertEquals('Bad Bot', VisitorLogger::typeLabel('bad_bot'));
        $this->t->assertEquals('Hacker', VisitorLogger::typeLabel('hacker'));
        $this->t->assertEquals('Human', VisitorLogger::typeLabel('human'));
    }

    public function testUnknownTypeFallsBackToTitleCase(): void
    {
        $this->t->assertEquals('Search Crawler', VisitorLogger::typeLabel('search_crawler'));
    }

    public function testFilterUrlSetsTheType(): void
    {
        $this->t->assertEquals(
            self::ADMIN . '/visitors?type=good_bot',
            VisitorLogger::typeFilterUrl(self::ADMIN, 'good_bot', [])
        );
    }

    public function testFilterUrlTogglesTheActiveTypeOff(): void
    {
        $this->t->assertEquals(
            self::ADMIN . '/visitors',
            VisitorLogger::typeFilterUrl(self::ADMIN, 'good_bot', ['type' => 'good_bot'])
        );
    }

    public function testFilterUrlKeepsTheOtherFiltersButDropsPagination(): void
    {
        $url = VisitorLogger::typeFilterUrl(self::ADMIN, 'hacker', [
            'type'     => 'good_bot',
            'bot_name' => 'Googlebot',
            'ip'       => '66.249.65.1',
            'page'     => '7',
        ]);

        $this->t->assertStringContains('type=hacker', $url);
        $this->t->assertStringContains('bot_name=Googlebot', $url);
        $this->t->assertStringContains('ip=66.249.65.1', $url);
        $this->t->assertNotContains('page=', $url);
    }

    public function testFilterUrlEncodesUserSuppliedFilters(): void
    {
        $url = VisitorLogger::typeFilterUrl(self::ADMIN, 'bad_bot', [
            'bot_name' => 'evil"><script>alert(1)</script>',
        ]);

        $this->t->assertNotContains('<script>', $url);
        $this->t->assertStringContains('type=bad_bot', $url);
    }

    /**
     * getStats() must report every known type, even when nothing was logged —
     * the summary cards render straight from its keys.
     */
    public function testStatsCoverEveryKnownTypeOnAnEmptyDatabase(): void
    {
        $dbPath = sys_get_temp_dir() . '/honeypot_visitor_test_' . uniqid() . '.sqlite';

        $db = new Database($dbPath);
        $db->initialize();

        $stats = (new VisitorLogger($db))->getStats(24);

        foreach (array_keys(VisitorLogger::TYPE_LABELS) as $type) {
            $this->t->assertArrayHasKey($type, $stats);
            $this->t->assertEquals(0, $stats[$type]);
        }

        @unlink($dbPath);
    }
}
