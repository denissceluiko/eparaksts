<?php

namespace Dencel\Eparaksts\Tests\SignAPI;

use Dencel\Eparaksts\SignAPI\v1\Configuration;
use Dencel\Eparaksts\SignAPI\v1\SignAPI;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Configuration::class)]
class ConfigurationTest extends TestCase
{
    private function make(array $responses, array &$container = []): SignAPI
    {
        $mock  = new MockHandler($responses);
        $stack = HandlerStack::create($mock);
        $stack->push(Middleware::history($container));
        return new SignAPI('client', 'secret', handlerStack: $stack);
    }

    public function testGetReturnsFullArray(): void
    {
        $data = ['clientId' => 'my-client', 'maxFileSize' => 10];
        $api  = $this->make([new Response(200, [], json_encode($data))]);

        $this->assertSame($data, $api->configuration()->get());
    }

    public function testGetWithKeyReturnsSpecificValue(): void
    {
        $data = ['clientId' => 'my-client', 'maxFileSize' => 10];
        $api  = $this->make([new Response(200, [], json_encode($data))]);

        $this->assertSame('my-client', $api->configuration()->get('clientId'));
    }

    public function testGetReturnsNullWhenKeyMissing(): void
    {
        $api = $this->make([new Response(200, [], json_encode(['a' => 1]))]);
        $this->assertNull($api->configuration()->get('missing'));
    }

    public function testGetReturnsNullOnEmptyResponse(): void
    {
        $api = $this->make([new Response(200, [], 'null')]);
        $this->assertNull($api->configuration()->get());
    }

    public function testPublicKeyUrlHasNoDoubleSlash(): void
    {
        $container = [];
        $api       = $this->make([new Response(200, [], json_encode(['publicKey' => 'pem']))], $container);

        $api->configuration()->publicKey();

        $uri = (string) $container[0]['request']->getUri();
        $this->assertStringNotContainsString('//', ltrim(str_replace('https://', '', $uri), '/'));
    }

    public function testPublicKeyReturnsDecodedBody(): void
    {
        $api    = $this->make([new Response(200, [], json_encode(['publicKey' => 'pem-content']))]);
        $result = $api->configuration()->publicKey();
        $this->assertSame('pem-content', $result['publicKey']);
    }
}
