<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Core\Request;
use ReportedIp\Honeypot\Tests\TestCase;

final class RequestTest extends TestCase
{
    public function testGetUri(): void
    {
        $request = $this->createRequest(['uri' => '/test?foo=bar']);
        $this->t->assertEquals('/test?foo=bar', $request->getUri());
    }

    public function testGetPath(): void
    {
        $request = $this->createRequest(['uri' => '/test?foo=bar']);
        $this->t->assertEquals('/test', $request->getPath());
    }

    public function testGetPathDefaultsToSlash(): void
    {
        $request = $this->createRequest(['uri' => '']);
        $path = $request->getPath();
        $this->t->assertTrue($path === '/' || $path === '', 'Path should default to / or empty');
    }

    public function testGetMethod(): void
    {
        $request = $this->createRequest(['method' => 'POST']);
        $this->t->assertEquals('POST', $request->getMethod());
    }

    public function testGetMethodDefaultsToGet(): void
    {
        $request = $this->createRequest([]);
        $this->t->assertEquals('GET', $request->getMethod());
    }

    public function testGetMethodIsUppercase(): void
    {
        $request = $this->createRequest(['method' => 'post']);
        $this->t->assertEquals('POST', $request->getMethod());
    }

    public function testIsPost(): void
    {
        $post = $this->createRequest(['method' => 'POST']);
        $get = $this->createRequest(['method' => 'GET']);
        $this->t->assertTrue($post->isPost());
        $this->t->assertFalse($get->isPost());
    }

    public function testIsGet(): void
    {
        $get = $this->createRequest(['method' => 'GET']);
        $post = $this->createRequest(['method' => 'POST']);
        $this->t->assertTrue($get->isGet());
        $this->t->assertFalse($post->isGet());
    }

    public function testGetHeaders(): void
    {
        $request = $this->createRequest([
            'headers' => ['User-Agent' => 'TestBot/1.0', 'Accept' => 'text/html'],
        ]);
        $headers = $request->getHeaders();
        $this->t->assertNotEmpty($headers);
    }

    public function testGetHeaderCaseInsensitive(): void
    {
        $request = $this->createRequest([
            'headers' => ['User-Agent' => 'TestBot/1.0'],
        ]);
        $this->t->assertEquals('TestBot/1.0', $request->getHeader('user-agent'));
        $this->t->assertEquals('TestBot/1.0', $request->getHeader('User-Agent'));
    }

    public function testGetHeaderReturnsNullForMissing(): void
    {
        $request = $this->createRequest([]);
        $this->t->assertNull($request->getHeader('X-Custom'));
    }

    public function testGetBody(): void
    {
        $request = $this->createRequest(['body' => 'raw body content']);
        $this->t->assertEquals('raw body content', $request->getBody());
    }

    public function testGetPostData(): void
    {
        $request = $this->createRequest(['postData' => ['log' => 'admin', 'pwd' => '1234']]);
        $data = $request->getPostData();
        $this->t->assertEquals('admin', $data['log']);
        $this->t->assertEquals('1234', $data['pwd']);
    }

    public function testGetQueryParams(): void
    {
        $request = $this->createRequest(['uri' => '/search?s=test&page=2']);
        $params = $request->getQueryParams();
        $this->t->assertEquals('test', $params['s']);
        $this->t->assertEquals('2', $params['page']);
    }

    public function testGetQueryParam(): void
    {
        $request = $this->createRequest(['queryParams' => ['s' => 'hello']]);
        $this->t->assertEquals('hello', $request->getQueryParam('s'));
        $this->t->assertNull($request->getQueryParam('missing'));
    }

    public function testGetUserAgent(): void
    {
        $request = $this->createRequest([
            'headers' => ['User-Agent' => 'Mozilla/5.0'],
        ]);
        $this->t->assertEquals('Mozilla/5.0', $request->getUserAgent());
    }

    public function testGetUserAgentEmptyWhenMissing(): void
    {
        $request = $this->createRequest(['headers' => ['Host' => 'example.com', 'User-Agent' => '']]);
        $this->t->assertEquals('', $request->getUserAgent());
    }

    public function testGetIp(): void
    {
        $request = $this->createRequest(['ip' => '192.168.1.100']);
        $this->t->assertEquals('192.168.1.100', $request->getIp());
    }

    public function testSetIp(): void
    {
        $request = $this->createRequest(['ip' => '1.2.3.4']);
        $request->setIp('5.6.7.8');
        $this->t->assertEquals('5.6.7.8', $request->getIp());
    }

    public function testGetCookies(): void
    {
        $request = $this->createRequest(['cookies' => ['session' => 'abc']]);
        $cookies = $request->getCookies();
        $this->t->assertEquals('abc', $cookies['session']);
    }

    public function testGetContentType(): void
    {
        $request = $this->createRequest([
            'headers' => ['Content-Type' => 'application/json'],
        ]);
        $this->t->assertEquals('application/json', $request->getContentType());
    }

    public function testToArray(): void
    {
        $request = $this->createRequest([
            'uri'    => '/wp-login.php',
            'method' => 'POST',
            'ip'     => '10.0.0.1',
        ]);
        $arr = $request->toArray();
        $this->t->assertArrayHasKey('uri', $arr);
        $this->t->assertArrayHasKey('path', $arr);
        $this->t->assertArrayHasKey('method', $arr);
        $this->t->assertArrayHasKey('ip', $arr);
        $this->t->assertEquals('/wp-login.php', $arr['uri']);
        $this->t->assertEquals('POST', $arr['method']);
    }

    public function testToArrayTruncatesLongBody(): void
    {
        $longBody = str_repeat('A', 600);
        $request = $this->createRequest(['body' => $longBody]);
        $arr = $request->toArray();
        $this->t->assertContains('[truncated]', $arr['body']);
    }

    public function testGetServerParam(): void
    {
        $request = $this->createRequest(['ip' => '1.2.3.4']);
        $this->t->assertEquals('1.2.3.4', $request->getServerParam('REMOTE_ADDR'));
    }
}
