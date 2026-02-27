<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Analyzers;

use ReportedIp\Honeypot\Detection\Analyzers\BruteForceAnalyzer;
use ReportedIp\Honeypot\Tests\TestCase;

final class BruteForceAnalyzerTest extends TestCase
{
    private BruteForceAnalyzer $analyzer;
    private string $counterDir;

    public function setUp(): void
    {
        $this->counterDir = sys_get_temp_dir() . '/honeypot_brute_test_' . uniqid();
        $this->analyzer = new BruteForceAnalyzer($this->counterDir);
    }

    public function tearDown(): void
    {
        // Cleanup counter files
        if (is_dir($this->counterDir)) {
            $files = glob($this->counterDir . '/*');
            if ($files) {
                foreach ($files as $f) {
                    @unlink($f);
                }
            }
            @rmdir($this->counterDir);
        }
    }

    public function testGetName(): void
    {
        $this->t->assertEquals('BruteForce', $this->analyzer->getName());
    }

    // --- Positive tests ---

    public function testDetectsPostToWpLogin(): void
    {
        $request = $this->createRequest([
            'uri'      => '/wp-login.php',
            'method'   => 'POST',
            'postData' => ['log' => 'admin', 'pwd' => 'password123'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertContains('login', $result->getComment());
    }

    public function testDetectsCommonUsername(): void
    {
        $request = $this->createRequest([
            'uri'      => '/wp-login.php',
            'method'   => 'POST',
            'postData' => ['log' => 'admin', 'pwd' => 'secret123'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertGreaterThanOrEqual(70, $result->getScore());
    }

    public function testDetectsCommonPassword(): void
    {
        $request = $this->createRequest([
            'uri'      => '/wp-login.php',
            'method'   => 'POST',
            'postData' => ['log' => 'admin', 'pwd' => 'password'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertGreaterThanOrEqual(75, $result->getScore());
    }

    public function testDetectsPostToLoginEndpoint(): void
    {
        $request = $this->createRequest([
            'uri'      => '/login',
            'method'   => 'POST',
            'postData' => ['username' => 'test', 'password' => 'test'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsPostToAdminLogin(): void
    {
        $request = $this->createRequest([
            'uri'      => '/admin/login',
            'method'   => 'POST',
            'postData' => ['user' => 'root', 'pass' => '12345'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    // --- Negative tests ---

    public function testIgnoresGetToLoginWithoutParams(): void
    {
        $request = $this->createRequest([
            'uri'    => '/wp-login.php',
            'method' => 'GET',
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testIgnoresPostToNonLoginPath(): void
    {
        $request = $this->createRequest([
            'uri'      => '/contact',
            'method'   => 'POST',
            'postData' => ['name' => 'John', 'message' => 'Hi'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testIgnoresGetToNormalPage(): void
    {
        $request = $this->createRequest([
            'uri'    => '/about',
            'method' => 'GET',
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testCategoriesAre18And31(): void
    {
        $request = $this->createRequest([
            'uri'      => '/wp-login.php',
            'method'   => 'POST',
            'postData' => ['log' => 'admin', 'pwd' => 'pass'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $categories = $result->getCategories();
        $this->t->assertTrue(in_array(18, $categories, true), 'Should include category 18');
        $this->t->assertTrue(in_array(31, $categories, true), 'Should include category 31');
    }
}
