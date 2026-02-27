<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Detection\PatternLibrary;
use ReportedIp\Honeypot\Tests\TestCase;

final class PatternLibraryTest extends TestCase
{
    public function testSqlInjectionPatternsReturnsArray(): void
    {
        $patterns = PatternLibrary::sqlInjectionPatterns();
        $this->t->assertNotEmpty($patterns);
    }

    public function testSqlInjectionPatternsCompile(): void
    {
        foreach (PatternLibrary::sqlInjectionPatterns() as $pattern) {
            $result = @preg_match($pattern, 'test');
            $this->t->assertTrue($result !== false, "Pattern failed to compile: {$pattern}");
        }
    }

    public function testXssPatternsReturnsArray(): void
    {
        $patterns = PatternLibrary::xssPatterns();
        $this->t->assertNotEmpty($patterns);
    }

    public function testXssPatternsCompile(): void
    {
        foreach (PatternLibrary::xssPatterns() as $pattern) {
            $result = @preg_match($pattern, 'test');
            $this->t->assertTrue($result !== false, "Pattern failed to compile: {$pattern}");
        }
    }

    public function testPathTraversalPatternsReturnsArray(): void
    {
        $patterns = PatternLibrary::pathTraversalPatterns();
        $this->t->assertNotEmpty($patterns);
    }

    public function testPathTraversalPatternsCompile(): void
    {
        foreach (PatternLibrary::pathTraversalPatterns() as $pattern) {
            $result = @preg_match($pattern, 'test');
            $this->t->assertTrue($result !== false, "Pattern failed to compile: {$pattern}");
        }
    }

    public function testSsrfPatternsReturnsArray(): void
    {
        $patterns = PatternLibrary::ssrfPatterns();
        $this->t->assertNotEmpty($patterns);
    }

    public function testSsrfPatternsCompile(): void
    {
        foreach (PatternLibrary::ssrfPatterns() as $pattern) {
            $result = @preg_match($pattern, 'test');
            $this->t->assertTrue($result !== false, "Pattern failed to compile: {$pattern}");
        }
    }

    public function testSuspiciousUserAgentsCompile(): void
    {
        foreach (PatternLibrary::suspiciousUserAgents() as $pattern) {
            $result = @preg_match($pattern, 'test');
            $this->t->assertTrue($result !== false, "Pattern failed to compile: {$pattern}");
        }
    }

    public function testSensitiveFilePathsCompile(): void
    {
        foreach (PatternLibrary::sensitiveFilePaths() as $pattern) {
            $result = @preg_match($pattern, 'test');
            $this->t->assertTrue($result !== false, "Pattern failed to compile: {$pattern}");
        }
    }

    public function testPluginExploitPathsCompile(): void
    {
        foreach (PatternLibrary::pluginExploitPaths() as $pattern) {
            $result = @preg_match($pattern, 'test');
            $this->t->assertTrue($result !== false, "Pattern failed to compile: {$pattern}");
        }
    }

    public function testSpamKeywordsCompile(): void
    {
        foreach (PatternLibrary::spamKeywords() as $pattern) {
            $result = @preg_match($pattern, 'test');
            $this->t->assertTrue($result !== false, "Pattern failed to compile: {$pattern}");
        }
    }

    public function testCvePatternsCompile(): void
    {
        foreach (PatternLibrary::cvePatterns() as $pattern) {
            $result = @preg_match($pattern, 'test');
            $this->t->assertTrue($result !== false, "Pattern failed to compile: {$pattern}");
        }
    }

    public function testShellPatternsCompile(): void
    {
        foreach (PatternLibrary::shellPatterns() as $pattern) {
            $result = @preg_match($pattern, 'test');
            $this->t->assertTrue($result !== false, "Pattern failed to compile: {$pattern}");
        }
    }

    public function testConfigFilePathsReturnsStrings(): void
    {
        $paths = PatternLibrary::configFilePaths();
        $this->t->assertNotEmpty($paths);
        foreach ($paths as $path) {
            $this->t->assertTrue(is_string($path), 'Config file path should be a string');
        }
    }

    public function testCommonUsernamesReturnsStrings(): void
    {
        $usernames = PatternLibrary::commonUsernames();
        $this->t->assertNotEmpty($usernames);
        $this->t->assertTrue(in_array('admin', $usernames, true));
    }

    public function testCommonPasswordsReturnsStrings(): void
    {
        $passwords = PatternLibrary::commonPasswords();
        $this->t->assertNotEmpty($passwords);
        $this->t->assertTrue(in_array('password', $passwords, true));
    }

    public function testXmlRpcMethodsReturnsStrings(): void
    {
        $methods = PatternLibrary::xmlRpcMethods();
        $this->t->assertNotEmpty($methods);
        $this->t->assertTrue(in_array('system.multicall', $methods, true));
    }

    public function testFakeSeoBotReturnsArray(): void
    {
        $bots = PatternLibrary::fakeSeoBot();
        $this->t->assertNotEmpty($bots);
        $this->t->assertArrayHasKey('Googlebot', $bots);
    }
}
