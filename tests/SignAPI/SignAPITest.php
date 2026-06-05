<?php

namespace Dencel\Eparaksts\Tests\SignAPI;

use Dencel\Eparaksts\SignAPI\v1\SignAPI;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(SignAPI::class)]
class SignAPITest extends TestCase
{
    private function make(array $responses, array &$container = []): SignAPI
    {
        $mock  = new MockHandler($responses);
        $stack = HandlerStack::create($mock);
        $stack->push(Middleware::history($container));
        return new SignAPI('client', 'secret', handlerStack: $stack);
    }

    public function testRequestAddsAuthorizationHeader(): void
    {
        $container = [];
        $api       = $this->make([new Response(200, [], '{}')], $container);
        $api->setToken(SignAPI::SCOPE_SIGNAPI, 'my-bearer', time() + 3600);

        $api->get('/some/path');

        $this->assertSame(
            'Bearer my-bearer',
            $container[0]['request']->getHeaderLine('authorization')
        );
    }

    public function testRequestBuildsCorrectUrl(): void
    {
        $container = [];
        $api       = $this->make([new Response(200, [], '{}')], $container);

        $api->get('/api-session/v1.0/start');

        $uri = (string) $container[0]['request']->getUri();
        $this->assertStringContainsString('/api-session/v1.0/start', $uri);
    }

    public function testUseMethodSetsToken(): void
    {
        $api = new SignAPI('client', 'secret');
        $api->use(['bearer' => 'tok', 'expires' => time() + 3600]);

        $this->assertSame('tok', $api->getBearer(SignAPI::SCOPE_SIGNAPI));
    }

    public function testFreshTokenReturnsFalseOnFailure(): void
    {
        $api = $this->make([new Response(401)]);
        $this->assertFalse($api->freshToken());
    }

    public function testFreshTokenSetsAndReturnsToken(): void
    {
        $api = $this->make([
            new Response(200, [], json_encode([
                'access_token' => 'fresh-token',
                'expires_in'   => 3600,
                'scope'        => SignAPI::SCOPE_SIGNAPI,
            ])),
        ]);

        $token = $api->freshToken();
        $this->assertIsArray($token);
        $this->assertSame('fresh-token', $token['bearer']);
        $this->assertSame('fresh-token', $api->getBearer(SignAPI::SCOPE_SIGNAPI));
    }

    public function testLazySubServicesAreSingletons(): void
    {
        $api = new SignAPI('client', 'secret');

        $this->assertSame($api->session(), $api->session());
        $this->assertSame($api->storage(), $api->storage());
        $this->assertSame($api->signing(), $api->signing());
        $this->assertSame($api->share(), $api->share());
        $this->assertSame($api->validation(), $api->validation());
        $this->assertSame($api->configuration(), $api->configuration());
    }
}
