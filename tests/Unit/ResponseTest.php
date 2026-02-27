<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Core\Response;
use ReportedIp\Honeypot\Tests\TestCase;

final class ResponseTest extends TestCase
{
    public function testDefaultStatusCode(): void
    {
        $response = new Response();
        $this->t->assertEquals(200, $response->getStatusCode());
    }

    public function testSetStatusCode(): void
    {
        $response = new Response();
        $result = $response->setStatusCode(404);
        $this->t->assertEquals(404, $response->getStatusCode());
        $this->t->assertInstanceOf(Response::class, $result);
    }

    public function testSetHeader(): void
    {
        $response = new Response();
        $result = $response->setHeader('X-Custom', 'value');
        $headers = $response->getHeaders();
        $this->t->assertEquals('value', $headers['X-Custom']);
        $this->t->assertInstanceOf(Response::class, $result);
    }

    public function testSetBody(): void
    {
        $response = new Response();
        $result = $response->setBody('<html>test</html>');
        $this->t->assertEquals('<html>test</html>', $response->getBody());
        $this->t->assertInstanceOf(Response::class, $result);
    }

    public function testSetContentType(): void
    {
        $response = new Response();
        $response->setContentType('text/html');
        $headers = $response->getHeaders();
        $this->t->assertEquals('text/html', $headers['Content-Type']);
    }

    public function testFluentInterface(): void
    {
        $response = new Response();
        $result = $response
            ->setStatusCode(201)
            ->setHeader('X-Test', 'yes')
            ->setBody('created')
            ->setContentType('text/plain');
        $this->t->assertInstanceOf(Response::class, $result);
        $this->t->assertEquals(201, $response->getStatusCode());
        $this->t->assertEquals('created', $response->getBody());
    }

    public function testGetHeadersReturnsEmptyByDefault(): void
    {
        $response = new Response();
        $this->t->assertEmpty($response->getHeaders());
    }

    public function testGetBodyReturnsEmptyByDefault(): void
    {
        $response = new Response();
        $this->t->assertEquals('', $response->getBody());
    }

    public function testMultipleHeadersAreMerged(): void
    {
        $response = new Response();
        $response->setHeader('X-One', '1');
        $response->setHeader('X-Two', '2');
        $headers = $response->getHeaders();
        $this->t->assertEquals('1', $headers['X-One']);
        $this->t->assertEquals('2', $headers['X-Two']);
    }

    public function testSetHeaderOverwritesPrevious(): void
    {
        $response = new Response();
        $response->setHeader('X-Test', 'first');
        $response->setHeader('X-Test', 'second');
        $headers = $response->getHeaders();
        $this->t->assertEquals('second', $headers['X-Test']);
    }
}
