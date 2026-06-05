<?php

namespace Dencel\Eparaksts\Tests\Traits;

use Dencel\Eparaksts\Eparaksts;
use Dencel\Eparaksts\Traits\CanRequestTokens;
use Dencel\Eparaksts\Traits\HasBasicAuthentication;
use Dencel\Eparaksts\Traits\HasScopedTokens;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(CanRequestTokens::class)]
class CanRequestTokensTest extends TestCase
{
    private function makeSubject(array $responses): object
    {
        $mock  = new MockHandler($responses);
        $stack = HandlerStack::create($mock);

        $subject = new class {
            use CanRequestTokens;
            use HasBasicAuthentication;
            use HasScopedTokens;
        };

        $subject->setUsername('client-id');
        $subject->setPassword('client-secret');
        $subject->setTokenHost('https://eidas.test');
        $subject->setHandlerStack($stack);

        return $subject;
    }

    public function testRequestTokenReturnsFalseOnNon200(): void
    {
        $subject = $this->makeSubject([new Response(401)]);
        $this->assertFalse($subject->requestToken(Eparaksts::GRANT_CLIENT_CREDENTIALS));
    }

    public function testRequestTokenReturnsFalseWhenResponseContainsError(): void
    {
        $subject = $this->makeSubject([
            new Response(200, [], json_encode(['error' => 'invalid_client'])),
        ]);

        $this->assertFalse($subject->requestToken(Eparaksts::GRANT_CLIENT_CREDENTIALS));
    }

    public function testRequestTokenSetsTokenAndReturnsIt(): void
    {
        $scope   = Eparaksts::SCOPE_IDENTIFICATION;
        $expires = 3600;

        $subject = $this->makeSubject([
            new Response(200, [], json_encode([
                'access_token' => 'my-bearer',
                'expires_in'   => $expires,
                'scope'        => $scope,
            ])),
        ]);

        $token = $subject->requestToken(Eparaksts::GRANT_CLIENT_CREDENTIALS, ['scope' => $scope]);

        $this->assertIsArray($token);
        $this->assertSame('my-bearer', $token['bearer']);
        $this->assertEqualsWithDelta(time() + $expires, $token['expires'], 2);
        $this->assertSame('my-bearer', $subject->getBearer($scope));
    }

    public function testRequestTokenSendsBasicAuthHeader(): void
    {
        $scope     = Eparaksts::SCOPE_IDENTIFICATION;
        $container = [];

        $mock = new MockHandler([
            new Response(200, [], json_encode([
                'access_token' => 'tok',
                'expires_in'   => 3600,
                'scope'        => $scope,
            ])),
        ]);
        $stack = HandlerStack::create($mock);
        $stack->push(Middleware::history($container));

        $subject = new class {
            use CanRequestTokens;
            use HasBasicAuthentication;
            use HasScopedTokens;
        };
        $subject->setUsername('user');
        $subject->setPassword('pass');
        $subject->setTokenHost('https://eidas.test');
        $subject->setHandlerStack($stack);

        $subject->requestToken(Eparaksts::GRANT_CLIENT_CREDENTIALS, ['scope' => $scope]);

        $this->assertStringStartsWith('Basic ', $container[0]['request']->getHeaderLine('authorization'));
    }
}
