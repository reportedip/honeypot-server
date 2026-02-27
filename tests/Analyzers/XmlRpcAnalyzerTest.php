<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Analyzers;

use ReportedIp\Honeypot\Detection\Analyzers\XmlRpcAnalyzer;
use ReportedIp\Honeypot\Tests\TestCase;

final class XmlRpcAnalyzerTest extends TestCase
{
    private XmlRpcAnalyzer $analyzer;

    public function setUp(): void
    {
        $this->analyzer = new XmlRpcAnalyzer();
    }

    public function testGetName(): void
    {
        $this->t->assertEquals('XmlRpc', $this->analyzer->getName());
    }

    // --- Positive tests ---

    public function testDetectsSystemMulticallPost(): void
    {
        $body = '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data><value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member></struct></value></data></array></value></param></params></methodCall>';
        $request = $this->createRequest([
            'uri'    => '/xmlrpc.php',
            'method' => 'POST',
            'body'   => $body,
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertGreaterThanOrEqual(80, $result->getScore());
    }

    public function testDetectsPingbackPing(): void
    {
        $body = '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>http://evil.com</string></value></param><param><value><string>http://target.com/post</string></value></param></params></methodCall>';
        $request = $this->createRequest([
            'uri'    => '/xmlrpc.php',
            'method' => 'POST',
            'body'   => $body,
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertContains('pingback', $result->getComment());
    }

    public function testDetectsGetUsersBlogsCredentialBrute(): void
    {
        $body = '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>admin</string></value></param><param><value><string>password123</string></value></param></params></methodCall>';
        $request = $this->createRequest([
            'uri'    => '/xmlrpc.php',
            'method' => 'POST',
            'body'   => $body,
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertGreaterThanOrEqual(85, $result->getScore());
    }

    public function testDetectsXmlRpcProbeGet(): void
    {
        $request = $this->createRequest([
            'uri'    => '/xmlrpc.php',
            'method' => 'GET',
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertContains('probe', $result->getComment());
    }

    public function testDetectsAnyPostToXmlrpc(): void
    {
        $request = $this->createRequest([
            'uri'    => '/xmlrpc.php',
            'method' => 'POST',
            'body'   => 'some xml body',
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
    }

    // --- Negative tests ---

    public function testIgnoresNonXmlRpcPaths(): void
    {
        $request = $this->createRequest([
            'uri'    => '/wp-login.php',
            'method' => 'POST',
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testIgnoresNormalGetRequest(): void
    {
        $request = $this->createRequest([
            'uri'    => '/about',
            'method' => 'GET',
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNull($result);
    }

    public function testCategoryIs33(): void
    {
        $request = $this->createRequest([
            'uri'    => '/xmlrpc.php',
            'method' => 'POST',
            'body'   => '<methodCall><methodName>system.listMethods</methodName></methodCall>',
        ]);
        $result = $this->analyzer->analyze($request);
        $this->t->assertNotNull($result);
        $this->t->assertTrue(in_array(33, $result->getCategories(), true), 'Should include category 33');
    }
}
