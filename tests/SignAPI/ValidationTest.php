<?php

namespace Dencel\Eparaksts\Tests\SignAPI;

use Dencel\Eparaksts\SignAPI\v1\SignAPI;
use Dencel\Eparaksts\SignAPI\v1\Validation;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Validation::class)]
class ValidationTest extends TestCase
{
    private function make(array $responses, array &$container = []): SignAPI
    {
        $mock  = new MockHandler($responses);
        $stack = HandlerStack::create($mock);
        $stack->push(Middleware::history($container));
        return new SignAPI('client', 'secret', handlerStack: $stack);
    }

    public function testValidateBuildsCorrectPath(): void
    {
        $container = [];
        $api       = $this->make([new Response(200, [], '{}')], $container);

        $api->validation()->validate('my-session', 'my-file');

        $uri = (string) $container[0]['request']->getUri();
        $this->assertStringContainsString('my-session', $uri);
        $this->assertStringContainsString('my-file', $uri);
        $this->assertStringContainsString('validate', $uri);
    }

    public function testValidateReturnsDecodedBody(): void
    {
        $api = $this->make([
            new Response(200, [], json_encode(['valid' => true, 'signatures' => []])),
        ]);

        $result = $api->validation()->validate('sess', 'file');
        $this->assertTrue($result['valid']);
    }
}
