<?php

namespace Dencel\Eparaksts\Tests\SignAPI;

use Dencel\Eparaksts\SignAPI\v1\Share;
use Dencel\Eparaksts\SignAPI\v1\SignAPI;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Share::class)]
class ShareTest extends TestCase
{
    private function make(array $responses, array &$container = []): SignAPI
    {
        $mock  = new MockHandler($responses);
        $stack = HandlerStack::create($mock);
        $stack->push(Middleware::history($container));
        return new SignAPI('client', 'secret', handlerStack: $stack);
    }

    public function testStartSendsJsonContentTypeHeader(): void
    {
        $container = [];
        $api       = $this->make([new Response(200, [], '{}')], $container);

        $api->share()->start('sess', [['personId' => '111111-11111', 'accessRights' => 5]]);

        $contentType = $container[0]['request']->getHeaderLine('Content-Type');
        $this->assertStringContainsString('application/json', $contentType);
    }

    public function testStartSendsPersonsInBody(): void
    {
        $container = [];
        $api       = $this->make([new Response(200, [], '{}')], $container);

        $people = [['personId' => '111111-11111', 'accessRights' => 5]];
        $api->share()->start('sess', $people, 'Please sign');

        $body = json_decode($container[0]['request']->getBody()->getContents(), true);
        $this->assertSame($people, $body['persons']);
        $this->assertSame('Please sign', $body['note']);
    }

    public function testDeleteBuildsCorrectPath(): void
    {
        $container = [];
        $api       = $this->make([new Response(200, [], '{}')], $container);

        $api->share()->delete('my-session', '111111-11111');

        $uri    = (string) $container[0]['request']->getUri();
        $method = $container[0]['request']->getMethod();

        $this->assertStringContainsString('my-session', $uri);
        $this->assertStringContainsString('111111-11111', $uri);
        $this->assertSame('DELETE', $method);
    }

    public function testPersonsBuildsCorrectPath(): void
    {
        $container = [];
        $api       = $this->make([new Response(200, [], '[]')], $container);

        $api->share()->persons('my-session');

        $uri = (string) $container[0]['request']->getUri();
        $this->assertStringContainsString('my-session', $uri);
        $this->assertStringContainsString('persons', $uri);
        $this->assertSame('GET', $container[0]['request']->getMethod());
    }

    public function testSessionsBuildsCorrectPath(): void
    {
        $container = [];
        $api       = $this->make([new Response(200, [], '[]')], $container);

        $api->share()->sessions('111111-11111');

        $uri = (string) $container[0]['request']->getUri();
        $this->assertStringContainsString('111111-11111', $uri);
        $this->assertStringContainsString('sessions', $uri);
    }
}
