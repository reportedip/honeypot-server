<?php

declare(strict_types=1);

namespace ReportedIp\Honeypot\Tests\Unit;

use ReportedIp\Honeypot\Api\ReportClient;
use ReportedIp\Honeypot\Tests\TestCase;

/**
 * Covers the detection of the API's "this IP is whitelisted" rejection.
 *
 * Response shape taken from ReportedIP_Whitelist_Manager::check_whitelist_before_report()
 * on reportedip.com: HTTP 400, code `ip_whitelisted`, plus a `whitelist_info`
 * payload carrying the category and reason.
 */
final class UpstreamWhitelistTest extends TestCase
{
    private const REJECTION = '{"code":"ip_whitelisted","message":"This IP address is whitelisted'
        . ' (Google: Google Bot and Google Services) and cannot be reported.","data":{"status":400,'
        . '"whitelist_info":{"whitelisted":true,"category":"Google","reason":"Google Bot and Google'
        . ' Services","source":"builtin"}}}';

    public function testRecognisesTheWhitelistRejection(): void
    {
        $this->t->assertTrue(ReportClient::isWhitelistRejection(400, self::REJECTION));
    }

    public function testIgnoresOtherRejections(): void
    {
        $this->t->assertFalse(ReportClient::isWhitelistRejection(
            400,
            '{"code":"rest_invalid_param","message":"Invalid parameter(s): categories"}'
        ));
        $this->t->assertFalse(ReportClient::isWhitelistRejection(
            403,
            '{"code":"invalid_api_key","message":"Invalid key"}'
        ));
        $this->t->assertFalse(ReportClient::isWhitelistRejection(429, 'rate limited'));
        $this->t->assertFalse(ReportClient::isWhitelistRejection(200, '{"success":true}'));
    }

    /**
     * A whitelist rejection is a 4xx, so the queue must still treat it as
     * permanent and stop retrying it.
     */
    public function testWhitelistRejectionStaysAPermanentRejection(): void
    {
        $this->t->assertTrue(ReportClient::isPermanentRejectionCode(400));
        $this->t->assertFalse(ReportClient::isTransientFailureCode(400));
    }

    public function testReasonIsBuiltFromCategoryAndReason(): void
    {
        $client = $this->clientWithResponse(400, self::REJECTION);

        $this->t->assertTrue($client->wasWhitelistedUpstream());
        $this->t->assertEquals(
            'Google: Google Bot and Google Services',
            $client->getWhitelistReason()
        );
    }

    public function testReasonFallsBackToTheApiMessage(): void
    {
        $client = $this->clientWithResponse(
            400,
            '{"code":"ip_whitelisted","message":"This IP address is whitelisted and cannot be reported.","data":{"status":400}}'
        );

        $this->t->assertEquals(
            'This IP address is whitelisted and cannot be reported.',
            $client->getWhitelistReason()
        );
    }

    public function testReasonFallsBackWhenTheBodyIsNotJson(): void
    {
        $client = $this->clientWithResponse(400, '<html>ip_whitelisted</html>');

        $this->t->assertTrue($client->wasWhitelistedUpstream());
        $this->t->assertEquals('whitelisted upstream', $client->getWhitelistReason());
    }

    public function testOtherRejectionsAreNotReportedAsWhitelisted(): void
    {
        $client = $this->clientWithResponse(
            403,
            '{"code":"invalid_api_key","message":"Invalid key"}'
        );

        $this->t->assertFalse($client->wasWhitelistedUpstream());
    }

    public function testReasonIsLengthCappedForTheDescriptionColumn(): void
    {
        $client = $this->clientWithResponse(400, json_encode([
            'code'    => 'ip_whitelisted',
            'message' => 'x',
            'data'    => [
                'status'         => 400,
                'whitelist_info' => [
                    'category' => 'Google',
                    'reason'   => str_repeat('a', 500),
                ],
            ],
        ], JSON_THROW_ON_ERROR));

        $this->t->assertLessThanOrEqual(200, mb_strlen($client->getWhitelistReason()));
    }

    /**
     * Build a client whose "last response" is the given API answer, without
     * making an HTTP request.
     */
    private function clientWithResponse(int $httpCode, string $body): ReportClient
    {
        $client = new ReportClient(new \ReportedIp\Honeypot\Core\Config([]));

        $reflection = new \ReflectionObject($client);

        $code = $reflection->getProperty('lastHttpCode');
        $code->setAccessible(true);
        $code->setValue($client, $httpCode);

        $response = $reflection->getProperty('lastResponseBody');
        $response->setAccessible(true);
        $response->setValue($client, $body);

        return $client;
    }
}
