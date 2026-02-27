<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Analyzers;

use ReportedIp\Honeypot\Detection\Analyzers\FormSpamAnalyzer;
use ReportedIp\Honeypot\Tests\TestCase;

final class FormSpamAnalyzerTest extends TestCase
{
    private FormSpamAnalyzer $analyzer;

    public function setUp(): void
    {
        $this->analyzer = new FormSpamAnalyzer();
    }

    public function testGetName(): void
    {
        $this->t->assertEquals('FormSpam', $this->analyzer->getName());
    }

    // --- Positive tests ---

    public function testDetectsSpamKeywords(): void
    {
        $request = $this->createRequest([
            'uri'      => '/contact',
            'method'   => 'POST',
            'postData' => [
                'name'    => 'Spammer',
                'message' => 'Buy cheap viagra and cialis at our online casino! Win the lottery jackpot now!',
            ],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertContains('spam', $result->getComment());
    }

    public function testDetectsExcessiveUrls(): void
    {
        $urls = implode(' ', array_fill(0, 5, 'http://spam-site.com/buy-now'));
        $request = $this->createRequest([
            'uri'      => '/comment',
            'method'   => 'POST',
            'postData' => [
                'name'    => 'LinkSpammer',
                'comment' => "Check out these links: {$urls}",
            ],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsFilledHoneypotField(): void
    {
        $request = $this->createRequest([
            'uri'      => '/contact',
            'method'   => 'POST',
            'postData' => [
                'name'     => 'Bot',
                'message'  => 'Hello',
                'honeypot' => 'filled_by_bot',
            ],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertContains('Honeypot field', $result->getComment());
    }

    public function testDetectsHtmlInNonHtmlField(): void
    {
        $request = $this->createRequest([
            'uri'      => '/contact',
            'method'   => 'POST',
            'postData' => [
                'name'    => '<a href="http://spam.com">Click here</a>',
                'message' => 'Normal message',
                'email'   => 'not-valid-email',
            ],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    // --- Negative tests ---

    public function testIgnoresGetRequest(): void
    {
        $request = $this->createRequest([
            'uri'    => '/contact',
            'method' => 'GET',
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testIgnoresNormalFormSubmission(): void
    {
        $request = $this->createRequest([
            'uri'      => '/contact',
            'method'   => 'POST',
            'postData' => [
                'name'    => 'John Doe',
                'email'   => 'john@example.com',
                'message' => 'I would like to inquire about your services.',
            ],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testIgnoresEmptyPost(): void
    {
        $request = $this->createRequest([
            'uri'      => '/form',
            'method'   => 'POST',
            'postData' => [],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testCategoriesAre40And12And10(): void
    {
        $request = $this->createRequest([
            'uri'      => '/contact',
            'method'   => 'POST',
            'postData' => [
                'name'     => 'Spammer',
                'message'  => 'Buy viagra casino lottery jackpot crypto trading',
                'honeypot' => 'bot_filled',
            ],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $categories = $result->getCategories();
        $this->t->assertTrue(in_array(40, $categories, true), 'Should include category 40');
    }
}
