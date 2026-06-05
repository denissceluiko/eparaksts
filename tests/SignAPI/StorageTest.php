<?php

namespace Dencel\Eparaksts\Tests\SignAPI;

use Dencel\Eparaksts\SignAPI\v1\SignAPI;
use Dencel\Eparaksts\SignAPI\v1\Storage;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Storage::class)]
class StorageTest extends TestCase
{
    private function make(array $responses, array &$container = []): SignAPI
    {
        $mock  = new MockHandler($responses);
        $stack = HandlerStack::create($mock);
        $stack->push(Middleware::history($container));
        return new SignAPI('client', 'secret', handlerStack: $stack);
    }

    public function testUploadReturnsNullOnNon201(): void
    {
        $api = $this->make([new Response(400)]);
        $this->assertNull($api->storage()->upload('sess', 'raw content', 'file.txt'));
    }

    public function testUploadRawContentSetsTextPlainMime(): void
    {
        $container = [];
        $api       = $this->make([new Response(201, [], json_encode(['fileId' => 'f1']))], $container);

        $api->storage()->upload('sess', 'raw file content', 'doc.txt');

        $body = (string) $container[0]['request']->getBody();
        $this->assertStringContainsString('text/plain', $body);
    }

    public function testUploadReturnsDecodedBody(): void
    {
        $api    = $this->make([new Response(201, [], json_encode(['fileId' => 'f1']))]);
        $result = $api->storage()->upload('sess', 'content', 'f.txt');
        $this->assertSame('f1', $result['fileId']);
    }

    public function testListReturnsNullOnNon200(): void
    {
        $api = $this->make([new Response(404)]);
        $this->assertNull($api->storage()->list('sess'));
    }

    public function testListReturnsFiles(): void
    {
        $api    = $this->make([new Response(200, [], json_encode([['fileId' => 'f1']]))]);
        $result = $api->storage()->list('sess');
        $this->assertSame('f1', $result[0]['fileId']);
    }

    public function testDownloadWithoutAsiceOmitsQueryParam(): void
    {
        $container = [];
        $api       = $this->make([new Response(200)], $container);

        $api->storage()->download('sess', 'file-id');

        $uri = (string) $container[0]['request']->getUri();
        $this->assertStringNotContainsString('type=', $uri);
    }

    public function testDownloadWithAsiceSendsQueryParam(): void
    {
        $container = [];
        $api       = $this->make([new Response(200)], $container);

        $api->storage()->download('sess', 'file-id', true);

        $uri = (string) $container[0]['request']->getUri();
        $this->assertStringContainsString('type=asice', $uri);
    }

    public function testAddDocumentDigestSendsJsonBody(): void
    {
        $container = [];
        $api       = $this->make([new Response(200, [], '{}')], $container);

        $files = [['name' => 'doc.pdf', 'digest' => 'abc=', 'digest_algorithm' => 'SHA256']];
        $api->storage()->addDocumentDigest('sess', $files);

        $request     = $container[0]['request'];
        $contentType = $request->getHeaderLine('Content-Type');
        $body        = json_decode($request->getBody()->getContents(), true);

        $this->assertStringContainsString('application/json', $contentType);
        $this->assertArrayHasKey('files', $body);
        $this->assertSame('doc.pdf', $body['files'][0]['name']);
    }

    public function testAddDocumentDigestNormalizesScalarInput(): void
    {
        $container = [];
        $api       = $this->make([new Response(200, [], '{}')], $container);

        $api->storage()->addDocumentDigest('sess', [
            'name' => 'doc.pdf', 'digest' => 'abc=', 'digest_algorithm' => 'SHA256',
        ]);

        $body = json_decode($container[0]['request']->getBody()->getContents(), true);
        $this->assertCount(1, $body['files']);
    }
}
