<?php

namespace Dencel\Eparaksts\Tests\SignAPI;

use Dencel\Eparaksts\SignAPI\v1\SignAPI;
use Dencel\Eparaksts\SignAPI\v1\Signing;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Signing::class)]
class SigningTest extends TestCase
{
    private function make(array $responses, array &$container = []): SignAPI
    {
        $mock  = new MockHandler($responses);
        $stack = HandlerStack::create($mock);
        $stack->push(Middleware::history($container));
        return new SignAPI('client', 'secret', handlerStack: $stack);
    }

    // --- calculateDigest ---

    public function testCalculateDigestUsesCapitalisedEndpoint(): void
    {
        $container = [];
        $api       = $this->make([new Response(200, [], '{}')], $container);

        $api->signing()->calculateDigest('sess-id', 'cert-base64');

        $uri = (string) $container[0]['request']->getUri();
        $this->assertStringContainsString('CalculateDigest', $uri);
    }

    public function testCalculateDigestNormalisesStringSession(): void
    {
        $container = [];
        $api       = $this->make([new Response(200, [], '{}')], $container);

        $api->signing()->calculateDigest('my-session', 'cert');

        $body = json_decode($container[0]['request']->getBody()->getContents(), true);
        $this->assertSame([['sessionId' => 'my-session']], $body['sessions']);
    }

    public function testCalculateDigestFiltersNullCreateNewEdoc(): void
    {
        $container = [];
        $api       = $this->make([new Response(200, [], '{}')], $container);

        $api->signing()->calculateDigest('sess', 'cert', false, null);

        $body = json_decode($container[0]['request']->getBody()->getContents(), true);
        $this->assertArrayNotHasKey('createNewEdoc', $body);
    }

    // --- finalizeSigning ---

    public function testFinalizeSigningWithTwoStrings(): void
    {
        $container = [];
        $api       = $this->make([new Response(200, [], '{}')], $container);

        $api->signing()->finalizeSigning('auth-cert', 'sess-id', 'sig-value');

        $body = json_decode($container[0]['request']->getBody()->getContents(), true);
        $this->assertCount(1, $body['sessionSignatureValues']);
        $this->assertSame('sess-id', $body['sessionSignatureValues'][0]['sessionId']);
        $this->assertSame('sig-value', $body['sessionSignatureValues'][0]['signatureValue']);
    }

    public function testFinalizeSigningWithAssocArray(): void
    {
        $container = [];
        $api       = $this->make([new Response(200, [], '{}')], $container);

        $api->signing()->finalizeSigning('auth-cert', ['sessionId' => 's1', 'signatureValue' => 'v1']);

        $body = json_decode($container[0]['request']->getBody()->getContents(), true);
        $this->assertSame('s1', $body['sessionSignatureValues'][0]['sessionId']);
    }

    public function testFinalizeSigningWithListArray(): void
    {
        $container = [];
        $api       = $this->make([new Response(200, [], '{}')], $container);

        $sessions = [
            ['sessionId' => 's1', 'signatureValue' => 'v1'],
            ['sessionId' => 's2', 'signatureValue' => 'v2'],
        ];
        $api->signing()->finalizeSigning('auth-cert', $sessions);

        $body = json_decode($container[0]['request']->getBody()->getContents(), true);
        $this->assertCount(2, $body['sessionSignatureValues']);
        $this->assertSame('s2', $body['sessionSignatureValues'][1]['sessionId']);
    }

    // --- addArchive ---

    public function testAddArchiveSendsCorrectBody(): void
    {
        $container = [];
        $api       = $this->make([new Response(200, [], '{}')], $container);

        $api->signing()->addArchive('auth-cert', 'sess-id');

        $body = json_decode($container[0]['request']->getBody()->getContents(), true);
        $this->assertSame('auth-cert', $body['authCertificate']);
        $this->assertSame([['sessionId' => 'sess-id']], $body['sessions']);
    }

    // --- normalizeSessions ---

    public function testNormaliseSessionsStringInput(): void
    {
        $container = [];
        $api       = $this->make([new Response(200, [], '{}')], $container);

        $api->signing()->calculateDigest('single-id', 'cert');

        $body = json_decode($container[0]['request']->getBody()->getContents(), true);
        $this->assertSame([['sessionId' => 'single-id']], $body['sessions']);
    }

    public function testNormaliseSessionsListArrayInput(): void
    {
        $container = [];
        $api       = $this->make([new Response(200, [], '{}')], $container);

        $api->signing()->calculateDigest(['id1', 'id2'], 'cert');

        $body = json_decode($container[0]['request']->getBody()->getContents(), true);
        $this->assertSame([['sessionId' => 'id1'], ['sessionId' => 'id2']], $body['sessions']);
    }

    // --- eSealCreate ---

    public function testESealCreateSendsCorrectBody(): void
    {
        $container = [];
        $api       = $this->make([new Response(200, [], '{}')], $container);

        $api->signing()->eSealCreate('sess', 'auth-cert', 'pfx-base64', 'enc-pass');

        $body = json_decode($container[0]['request']->getBody()->getContents(), true);
        $this->assertSame('auth-cert', $body['authCertificate']);
        $this->assertSame('pfx-base64', $body['signKey']);
        $this->assertSame('enc-pass', $body['signKeyPassword']);
    }
}
