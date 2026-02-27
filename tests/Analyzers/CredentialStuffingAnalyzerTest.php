<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Analyzers;

use ReportedIp\Honeypot\Detection\Analyzers\CredentialStuffingAnalyzer;
use ReportedIp\Honeypot\Tests\TestCase;

final class CredentialStuffingAnalyzerTest extends TestCase
{
    private CredentialStuffingAnalyzer $analyzer;

    public function setUp(): void
    {
        $this->analyzer = new CredentialStuffingAnalyzer();
    }

    public function testGetName(): void
    {
        $this->t->assertEquals('CredentialStuffing', $this->analyzer->getName());
    }

    // --- Positive tests ---

    public function testDetectsAdminPasswordCombo(): void
    {
        $request = $this->createRequest([
            'uri'      => '/login',
            'method'   => 'POST',
            'postData' => ['username' => 'admin', 'password' => 'password'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertGreaterThanOrEqual(85, $result->getScore());
    }

    public function testDetectsRootDefault(): void
    {
        $request = $this->createRequest([
            'uri'      => '/login',
            'method'   => 'POST',
            'postData' => ['username' => 'root', 'password' => '123456'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsCommonUsernameOnly(): void
    {
        $request = $this->createRequest([
            'uri'      => '/login',
            'method'   => 'POST',
            'postData' => ['username' => 'admin', 'password' => 'my_unique_pass_xyz'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsBasicAuthWithDefaultCredentials(): void
    {
        $encoded = base64_encode('admin:password');
        $request = $this->createRequest([
            'uri'     => '/api/data',
            'method'  => 'GET',
            'headers' => ['Authorization' => 'Basic ' . $encoded],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertGreaterThanOrEqual(85, $result->getScore());
    }

    public function testDetectsJsonCredentials(): void
    {
        $body = json_encode(['username' => 'admin', 'password' => 'admin']);
        $request = $this->createRequest([
            'uri'     => '/api/login',
            'method'  => 'POST',
            'headers' => ['Content-Type' => 'application/json'],
            'body'    => $body,
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    public function testDetectsShortBearerToken(): void
    {
        $request = $this->createRequest([
            'uri'     => '/api/data',
            'method'  => 'GET',
            'headers' => ['Authorization' => 'Bearer abc'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    // --- Negative tests ---

    public function testIgnoresUniqueCredentials(): void
    {
        $request = $this->createRequest([
            'uri'      => '/login',
            'method'   => 'POST',
            'postData' => ['username' => 'j4n3_d03_xyz', 'password' => 'S3cur3P@ssw0rd!2024#Rand0m'],
        ]);
        $result = $this->analyzer->analyze($request);
        // Should still detect (any POST with creds to honeypot is suspicious)
        // but score should be lower for non-common creds
        if ($result !== null) {
            $this->t->assertLessThanOrEqual(70, $result->getScore());
        }
    }

    public function testIgnoresGetWithoutAuth(): void
    {
        $request = $this->createRequest([
            'uri'    => '/page',
            'method' => 'GET',
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testCategoriesAre18And15(): void
    {
        $request = $this->createRequest([
            'uri'      => '/login',
            'method'   => 'POST',
            'postData' => ['username' => 'admin', 'password' => 'admin'],
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $categories = $result->getCategories();
        $this->t->assertTrue(in_array(18, $categories, true), 'Should include category 18');
        $this->t->assertTrue(in_array(15, $categories, true), 'Should include category 15');
    }
}
