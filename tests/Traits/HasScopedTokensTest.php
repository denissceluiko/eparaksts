<?php

namespace Dencel\Eparaksts\Tests\Traits;

use Dencel\Eparaksts\Eparaksts;
use Dencel\Eparaksts\Traits\HasScopedTokens;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(HasScopedTokens::class)]
class HasScopedTokensTest extends TestCase
{
    private object $subject;

    protected function setUp(): void
    {
        $this->subject = new class {
            use HasScopedTokens;
        };
    }

    public function testGetValidScopesReturnsAllScopes(): void
    {
        $scopes = $this->subject->getValidScopes();

        $this->assertContains(Eparaksts::SCOPE_IDENTIFICATION, $scopes);
        $this->assertContains(Eparaksts::SCOPE_IDENTIFICATION_WITH_AGE, $scopes);
        $this->assertContains(Eparaksts::SCOPE_IDENTIFICATION_WITH_AGE_14, $scopes);
        $this->assertContains(Eparaksts::SCOPE_IDENTIFICATION_WITH_AGE_16, $scopes);
        $this->assertContains(Eparaksts::SCOPE_IDENTIFICATION_WITH_AGE_18, $scopes);
        $this->assertContains(Eparaksts::SCOPE_IDENTIFICATION_WITH_AGE_21, $scopes);
        $this->assertContains(Eparaksts::SCOPE_SIGNAPI, $scopes);
        $this->assertContains(Eparaksts::SCOPE_SIGNATURE, $scopes);
        $this->assertContains(Eparaksts::SCOPE_SIGNING_IDENTITY, $scopes);
    }

    public function testIsValidScopeReturnsTrueForKnownScope(): void
    {
        $this->assertTrue($this->subject->isValidScope(Eparaksts::SCOPE_IDENTIFICATION));
        $this->assertTrue($this->subject->isValidScope(Eparaksts::SCOPE_SIGNAPI));
    }

    public function testIsValidScopeReturnsFalseForUnknownScope(): void
    {
        $this->assertFalse($this->subject->isValidScope('invalid:scope'));
    }

    public function testSetScopeReturnsFalseForInvalidScope(): void
    {
        $this->assertFalse($this->subject->setScope('invalid:scope'));
        $this->assertNull($this->subject->getScope());
    }

    public function testSetAndGetScope(): void
    {
        $this->subject->setScope(Eparaksts::SCOPE_IDENTIFICATION);
        $this->assertSame(Eparaksts::SCOPE_IDENTIFICATION, $this->subject->getScope());
    }

    public function testSetAndGetToken(): void
    {
        $expires = time() + 3600;
        $this->subject->setToken(Eparaksts::SCOPE_IDENTIFICATION, 'bearer-token', $expires);

        $token = $this->subject->getToken(Eparaksts::SCOPE_IDENTIFICATION);
        $this->assertSame('bearer-token', $token['bearer']);
        $this->assertSame($expires, $token['expires']);
    }

    public function testSetTokenReturnsFalseForInvalidScope(): void
    {
        $this->assertFalse($this->subject->setToken('bad:scope', 'token', time() + 60));
    }

    public function testGetTokenFallsBackToCurrentScope(): void
    {
        $this->subject->setScope(Eparaksts::SCOPE_IDENTIFICATION);
        $this->subject->setToken(Eparaksts::SCOPE_IDENTIFICATION, 'scoped-token', time() + 3600);

        $this->assertSame('scoped-token', $this->subject->getToken()['bearer']);
    }

    public function testGetBearerReturnsNullWhenNoToken(): void
    {
        $this->assertNull($this->subject->getBearer(Eparaksts::SCOPE_IDENTIFICATION));
    }

    public function testIsExpiredReturnsTrueForPastExpiry(): void
    {
        $this->subject->setScope(Eparaksts::SCOPE_IDENTIFICATION);
        $this->subject->setToken(Eparaksts::SCOPE_IDENTIFICATION, 'old-token', time() - 1);

        $this->assertTrue($this->subject->isExpired());
    }

    public function testIsExpiredReturnsFalseForFutureExpiry(): void
    {
        $this->subject->setScope(Eparaksts::SCOPE_IDENTIFICATION);
        $this->subject->setToken(Eparaksts::SCOPE_IDENTIFICATION, 'valid-token', time() + 3600);

        $this->assertFalse($this->subject->isExpired());
    }

    public function testHasValidTokenReturnsFalseForExpiredToken(): void
    {
        $this->subject->setToken(Eparaksts::SCOPE_IDENTIFICATION, 'old', time() - 1);
        $this->assertFalse($this->subject->hasValidToken(Eparaksts::SCOPE_IDENTIFICATION));
    }

    public function testHasValidTokenReturnsTrueForValidToken(): void
    {
        $this->subject->setToken(Eparaksts::SCOPE_IDENTIFICATION, 'valid', time() + 3600);
        $this->assertTrue($this->subject->hasValidToken(Eparaksts::SCOPE_IDENTIFICATION));
    }

    public function testSetTokensBulk(): void
    {
        $tokens = [
            Eparaksts::SCOPE_IDENTIFICATION => ['bearer' => 'tok1', 'expires' => time() + 3600],
            Eparaksts::SCOPE_SIGNAPI        => ['bearer' => 'tok2', 'expires' => time() + 7200],
        ];

        $this->subject->setTokens($tokens);

        $this->assertSame('tok1', $this->subject->getBearer(Eparaksts::SCOPE_IDENTIFICATION));
        $this->assertSame('tok2', $this->subject->getBearer(Eparaksts::SCOPE_SIGNAPI));
    }

    public function testSetTokensSkipsInvalidEntries(): void
    {
        $this->subject->setTokens([
            Eparaksts::SCOPE_IDENTIFICATION => ['bearer' => '', 'expires' => time() + 3600],
            Eparaksts::SCOPE_SIGNAPI        => ['bearer' => 'tok', 'expires' => 0],
        ]);

        $this->assertNull($this->subject->getBearer(Eparaksts::SCOPE_IDENTIFICATION));
    }

    public function testGetExpiresIn(): void
    {
        $this->subject->setScope(Eparaksts::SCOPE_IDENTIFICATION);
        $this->subject->setToken(Eparaksts::SCOPE_IDENTIFICATION, 'tok', time() + 100);

        $this->assertEqualsWithDelta(100, $this->subject->getExpiresIn(), 2);
    }
}
