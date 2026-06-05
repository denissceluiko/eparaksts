<?php

namespace Dencel\Eparaksts\Tests;

use Dencel\Eparaksts\Eparaksts;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(Eparaksts::class)]
class EparakststTest extends TestCase
{
    private function make(array $responses, array &$container = []): Eparaksts
    {
        $mock  = new MockHandler($responses);
        $stack = HandlerStack::create($mock);
        $stack->push(Middleware::history($container));
        return new Eparaksts('client', 'secret', handlerStack: $stack);
    }

    // --- authorize() ---

    public function testAuthorizeReturnsUrlWithRedirectUri(): void
    {
        $e   = new Eparaksts('client', 'secret');
        $url = $e->authorize(Eparaksts::SCOPE_IDENTIFICATION, 'state123', 'https://app.test/cb');

        $this->assertStringContainsString('redirect_uri=', $url);
        $this->assertStringNotContainsString('redirect_url=', $url);
        $this->assertStringContainsString('state=state123', $url);
        $this->assertStringContainsString('client_id=client', $url);
    }

    public function testAuthorizeOmitsEmptyRedirect(): void
    {
        $e   = new Eparaksts('client', 'secret');
        $url = $e->authorize(Eparaksts::SCOPE_IDENTIFICATION, 'state');

        $this->assertStringNotContainsString('redirect_uri', $url);
    }

    // --- logout() ---

    public function testLogoutReturnsUrlWithRedirectUri(): void
    {
        $e   = new Eparaksts('client', 'secret');
        $url = $e->logout('https://app.test/');

        $this->assertStringContainsString('redirect_uri=', $url);
        $this->assertStringContainsString('logout', $url);
    }

    // --- me() ---

    public function testMeSendsGetRequest(): void
    {
        $container = [];
        $e         = $this->make([new Response(200, [], json_encode(['sub' => 'abc']))], $container);
        $e->setToken(Eparaksts::SCOPE_IDENTIFICATION, 'tok', time() + 3600);

        $e->me(Eparaksts::SCOPE_IDENTIFICATION);

        $this->assertSame('GET', $container[0]['request']->getMethod());
    }

    public function testMeReturnsEmptyArrayOnNon200(): void
    {
        $e = $this->make([new Response(401)]);
        $e->setToken(Eparaksts::SCOPE_IDENTIFICATION, 'tok', time() + 3600);

        $this->assertSame([], $e->me(Eparaksts::SCOPE_IDENTIFICATION));
    }

    public function testMeReturnsDecodedBody(): void
    {
        $e = $this->make([new Response(200, [], json_encode(['sub' => 'user-1']))]);
        $e->setToken(Eparaksts::SCOPE_IDENTIFICATION, 'tok', time() + 3600);

        $result = $e->me(Eparaksts::SCOPE_IDENTIFICATION);
        $this->assertSame('user-1', $result['sub']);
    }

    // --- sign() ---

    public function testSignReturnsNullForInvalidAlgorithm(): void
    {
        $e = new Eparaksts('client', 'secret');
        $this->assertNull($e->sign('digest', 'md5', 'identity-id'));
    }

    public function testSignReturnsNullOnNon200(): void
    {
        $e = $this->make([new Response(400)]);
        $e->setToken(Eparaksts::SCOPE_SIGNATURE, 'tok', time() + 3600);

        $this->assertNull($e->sign('digest', 'rsa-sha256', 'identity-id'));
    }

    public function testSignReturnsBodyOn200(): void
    {
        $e = $this->make([new Response(200, [], 'base64signature')]);
        $e->setToken(Eparaksts::SCOPE_SIGNATURE, 'tok', time() + 3600);

        $this->assertSame('base64signature', $e->sign('digest', 'ecdsa', 'identity-id'));
    }

    public function testSignPassesAlgorithmThrough(): void
    {
        $container = [];
        $e         = $this->make([new Response(200, [], 'sig')], $container);
        $e->setToken(Eparaksts::SCOPE_SIGNATURE, 'tok', time() + 3600);

        $e->sign('digest', 'rsa-sha384', 'identity-id');

        $body = json_decode($container[0]['request']->getBody()->getContents(), true);
        $this->assertSame('rsa-sha384', $body['signature_algorithm']);
    }

    // --- signBatch() ---

    public function testSignBatchReturnsNullForInvalidAlgorithm(): void
    {
        $e = new Eparaksts('client', 'secret');
        $this->assertNull($e->signBatch([['digest_value' => 'x']], 'md5', 'id'));
    }

    public function testSignBatchReturnsNullOnNon200(): void
    {
        $e = $this->make([new Response(400)]);
        $e->setToken(Eparaksts::SCOPE_SIGNATURE, 'tok', time() + 3600);

        $this->assertNull($e->signBatch([['digest_value' => 'x']], 'rsa-sha256', 'id'));
    }

    public function testSignBatchReturnsDecodedArrayOn200(): void
    {
        $e = $this->make([new Response(200, [], json_encode([['signature' => 'abc']]))]);
        $e->setToken(Eparaksts::SCOPE_SIGNATURE, 'tok', time() + 3600);

        $result = $e->signBatch([['digest_value' => 'x']], 'rsa-sha256', 'id');
        $this->assertSame('abc', $result[0]['signature']);
    }

    // --- findIdentity() / filterIdentities() ---

    private function identities(): array
    {
        return [
            [
                'labels'      => ['mobileid', 'x509:keyUsage:digitalSignature', 'eparaksts'],
                'description' => 'eparaksts:mobileid:auth',
                'status'      => ['value' => 'enabled'],
                'details'     => ['certificate' => 'cert-auth'],
            ],
            [
                'labels'      => ['mobileid', 'x509:keyUsage:contentCommitment', 'eparaksts'],
                'description' => 'eparaksts:mobileid:sign',
                'status'      => ['value' => 'enabled'],
                'details'     => ['certificate' => 'cert-sign'],
            ],
            [
                'labels'      => ['serverid', 'eparaksts'],
                'description' => 'eparaksts:serverid',
                'status'      => ['value' => 'enabled'],
                'details'     => ['certificate' => 'cert-serverid'],
            ],
            [
                'labels'      => ['qsealc', 'x509:keyUsage:contentCommitment', 'eparaksts'],
                'description' => 'eparaksts:qsealc:sign',
                'status'      => ['value' => 'enabled'],
                'details'     => ['certificate' => 'cert-qseal'],
            ],
        ];
    }

    public function testFindIdentityReturnsNullForUnknownType(): void
    {
        $e = new Eparaksts('client', 'secret');
        $this->assertNull($e->findIdentity('unknown', $this->identities()));
    }

    public function testFindIdentityReturnsMobileidAuth(): void
    {
        $e        = new Eparaksts('client', 'secret');
        $identity = $e->findIdentity(Eparaksts::CERT_MOBILEID_AUTH, $this->identities());

        $this->assertSame('cert-auth', $identity['details']['certificate']);
    }

    public function testFindIdentityReturnsMobileidSign(): void
    {
        $e        = new Eparaksts('client', 'secret');
        $identity = $e->findIdentity(Eparaksts::CERT_MOBILEID_SIGN, $this->identities());

        $this->assertSame('cert-sign', $identity['details']['certificate']);
    }

    public function testFindIdentityReturnsSigning(): void
    {
        $e        = new Eparaksts('client', 'secret');
        $identity = $e->findIdentity(Eparaksts::CERT_SIGNING, $this->identities());

        $this->assertSame('cert-serverid', $identity['details']['certificate']);
    }

    public function testFindIdentityReturnsQseal(): void
    {
        $e        = new Eparaksts('client', 'secret');
        $identity = $e->findIdentity(Eparaksts::CERT_QSEAL, $this->identities());

        $this->assertSame('cert-qseal', $identity['details']['certificate']);
    }

    public function testFindIdentityReturnsNullWhenNoneMatch(): void
    {
        $e = new Eparaksts('client', 'secret');
        $this->assertNull($e->findIdentity(Eparaksts::CERT_QSEAL, []));
    }

    public function testFilterIdentitiesExcludesDisabledIdentities(): void
    {
        $e = new Eparaksts('client', 'secret');

        $identities = [
            [
                'labels'      => ['mobileid', 'x509:keyUsage:digitalSignature'],
                'description' => 'eparaksts:mobileid:auth',
                'status'      => ['value' => 'disabled'],
                'details'     => ['certificate' => 'cert-disabled'],
            ],
        ];

        $this->assertNull($e->findIdentity(Eparaksts::CERT_MOBILEID_AUTH, $identities));
    }

    public function testFilterIdentitiesRequiresAllNeedlesToMatch(): void
    {
        $e = new Eparaksts('client', 'secret');

        $identities = [
            [
                'labels'      => ['mobileid', 'x509:keyUsage:digitalSignature'],
                'description' => 'wrong-description',
                'status'      => ['value' => 'enabled'],
                'details'     => ['certificate' => 'cert'],
            ],
        ];

        $this->assertNull($e->findIdentity(Eparaksts::CERT_MOBILEID_AUTH, $identities));
    }

    public function testFindCertReturnsNullWhenNotFound(): void
    {
        $e = new Eparaksts('client', 'secret');
        $this->assertNull($e->findCert(Eparaksts::CERT_MOBILEID_AUTH, []));
    }

    public function testFindCertReturnsCertificate(): void
    {
        $e = new Eparaksts('client', 'secret');
        $this->assertSame('cert-auth', $e->findCert(Eparaksts::CERT_MOBILEID_AUTH, $this->identities()));
    }

    // --- serialize / unserialize ---

    public function testSerializeRoundTrip(): void
    {
        $e = new Eparaksts('client', 'secret', 'https://custom.host');
        $e->setScope(Eparaksts::SCOPE_IDENTIFICATION);
        $e->setToken(Eparaksts::SCOPE_IDENTIFICATION, 'bearer', time() + 3600);

        $restored = unserialize(serialize($e));

        $this->assertSame('client', $restored->getUsername());
        $this->assertSame('secret', $restored->getPassword());
        $this->assertSame('https://custom.host', $restored->getHost());
        $this->assertSame('bearer', $restored->getBearer(Eparaksts::SCOPE_IDENTIFICATION));
    }

    // --- isAuthenticated() ---

    public function testIsAuthenticatedReturnsFalseWithNoToken(): void
    {
        $e = new Eparaksts('client', 'secret');
        $e->setScope(Eparaksts::SCOPE_IDENTIFICATION);
        $this->assertFalse($e->isAuthenticated());
    }

    public function testIsAuthenticatedReturnsTrueWithValidToken(): void
    {
        $e = new Eparaksts('client', 'secret');
        $e->setScope(Eparaksts::SCOPE_IDENTIFICATION);
        $e->setToken(Eparaksts::SCOPE_IDENTIFICATION, 'bearer', time() + 3600);
        $this->assertTrue($e->isAuthenticated());
    }
}
