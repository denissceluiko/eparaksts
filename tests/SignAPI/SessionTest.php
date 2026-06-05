<?php

namespace Dencel\Eparaksts\Tests\SignAPI;

use Dencel\Eparaksts\SignAPI\v1\Session;
use Dencel\Eparaksts\SignAPI\v1\SignAPI;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Session::class)]
class SessionTest extends TestCase
{
    private function make(array $responses, array &$container = []): SignAPI
    {
        $mock  = new MockHandler($responses);
        $stack = HandlerStack::create($mock);
        $stack->push(Middleware::history($container));
        return new SignAPI('client', 'secret', handlerStack: $stack);
    }

    public function testStartReturnsNullOnNon201(): void
    {
        $api = $this->make([new Response(200, [], '{}')]);
        $this->assertNull($api->session()->start());
    }

    public function testStartReturnsSessionId(): void
    {
        $api = $this->make([
            new Response(201, [], json_encode(['sessionId' => 'abc123'])),
        ]);

        $result = $api->session()->start();
        $this->assertSame('abc123', $result['sessionId']);
    }

    public function testStartPassesAmountParam(): void
    {
        $container = [];
        $api       = $this->make([new Response(201, [], json_encode([]))], $container);

        $api->session()->start(3);

        $uri = (string) $container[0]['request']->getUri();
        $this->assertStringContainsString('amount=3', $uri);
    }

    public function testCloseReturnsNullOnNon200(): void
    {
        $api = $this->make([new Response(404)]);
        $this->assertNull($api->session()->close('session-id'));
    }

    public function testCloseReturnsBody(): void
    {
        $api = $this->make([
            new Response(200, [], json_encode(['message' => 'Session abc closed'])),
        ]);

        $result = $api->session()->close('abc');
        $this->assertStringContainsString('abc', $result['message']);
    }

    public function testCloseUsesSessionIdInPath(): void
    {
        $container = [];
        $api       = $this->make([new Response(200, [], '{}')], $container);

        $api->session()->close('my-session-id');

        $uri = (string) $container[0]['request']->getUri();
        $this->assertStringContainsString('my-session-id', $uri);
    }
}
