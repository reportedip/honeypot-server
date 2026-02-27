<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Core\Config;
use ReportedIp\Honeypot\Core\Router;
use ReportedIp\Honeypot\Profile\WordPressProfile;
use ReportedIp\Honeypot\Tests\TestCase;

final class RouterTest extends TestCase
{
    private Router $router;

    public function setUp(): void
    {
        $profile = new WordPressProfile();
        $config = new Config(['admin_path' => '/_hp_admin']);
        $this->router = new Router($profile, $config);
    }

    public function testRouteLoginPage(): void
    {
        $request = $this->createRequest(['uri' => '/wp-login.php']);
        $result = $this->router->route($request);
        $this->t->assertEquals('login', $result['trap']);
    }

    public function testRouteXmlRpc(): void
    {
        $request = $this->createRequest(['uri' => '/xmlrpc.php']);
        $result = $this->router->route($request);
        $this->t->assertEquals('xmlrpc', $result['trap']);
    }

    public function testRouteRestApi(): void
    {
        $request = $this->createRequest(['uri' => '/wp-json/wp/v2/posts']);
        $result = $this->router->route($request);
        $this->t->assertEquals('api', $result['trap']);
    }

    public function testRouteAdmin(): void
    {
        $request = $this->createRequest(['uri' => '/wp-admin/']);
        $result = $this->router->route($request);
        $this->t->assertEquals('cms_admin', $result['trap']);
    }

    public function testRouteComment(): void
    {
        $request = $this->createRequest(['uri' => '/wp-comments-post.php', 'method' => 'POST']);
        $result = $this->router->route($request);
        $this->t->assertEquals('comment', $result['trap']);
    }

    public function testRouteHome(): void
    {
        $request = $this->createRequest(['uri' => '/']);
        $result = $this->router->route($request);
        $this->t->assertEquals('home', $result['trap']);
    }

    public function testRouteNotFound(): void
    {
        $request = $this->createRequest(['uri' => '/some-random-page']);
        $result = $this->router->route($request);
        $this->t->assertEquals('not_found', $result['trap']);
    }

    public function testRouteHoneypotAdminPanel(): void
    {
        $request = $this->createRequest(['uri' => '/_hp_admin']);
        $result = $this->router->route($request);
        $this->t->assertEquals('admin', $result['trap']);
    }

    public function testRouteHoneypotAdminSubpath(): void
    {
        $request = $this->createRequest(['uri' => '/_hp_admin/logs']);
        $result = $this->router->route($request);
        $this->t->assertEquals('admin', $result['trap']);
    }

    public function testIsAdminPath(): void
    {
        $request = $this->createRequest(['uri' => '/_hp_admin']);
        $this->t->assertTrue($this->router->isAdminPath($request));

        $request2 = $this->createRequest(['uri' => '/wp-admin/']);
        $this->t->assertFalse($this->router->isAdminPath($request2));
    }

    public function testRouteContact(): void
    {
        $request = $this->createRequest(['uri' => '/contact']);
        $result = $this->router->route($request);
        $this->t->assertEquals('contact', $result['trap']);
    }

    public function testRouteVulnerabilityPath(): void
    {
        $request = $this->createRequest(['uri' => '/wp-content/plugins/revslider/']);
        $result = $this->router->route($request);
        $this->t->assertEquals('vulnerability', $result['trap']);
        $this->t->assertArrayHasKey('path', $result['params']);
    }
}
