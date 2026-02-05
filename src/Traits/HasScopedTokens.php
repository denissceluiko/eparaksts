<?php

namespace Dencel\Eparaksts\Traits;

trait HasScopedTokens
{
    protected array $tokens = [];
    protected ?string $scope = null;

    public const SCOPE_IDENTIFICATION           = 'urn:lvrtc:fpeil:aa';
    public const SCOPE_IDENTIFICATION_WITH_AGE  = 'urn:lvrtc:fpeil:aa:age';
    public const SCOPE_SIGNING_IDENTITY         = 'urn:safelayer:eidas:sign:identity:profile';
    public const SCOPE_SIGNATURE                = 'urn:safelayer:eidas:sign:identity:use:server';
    public const SCOPE_SIGNAPI                  = 'urn:safelayer:eidas:oauth:token:introspect';

    public function getValidScopes(): array
    {
        return [
            static::SCOPE_IDENTIFICATION,
            static::SCOPE_IDENTIFICATION_WITH_AGE,
            static::SCOPE_SIGNAPI,
            static::SCOPE_SIGNATURE,
            static::SCOPE_SIGNING_IDENTITY,
        ];
    }

    public function isValidScope(string $scope): bool
    {
        return in_array($scope, $this->getValidScopes());
    }

    public function setScope(string $scope): bool
    {
        if (!$this->isValidScope($scope)) {
            return false;
        }

        $this->scope = $scope;

        return true;
    }

    public function getScope(): ?string
    {
        return $this->scope;
    }

    public function getToken(?string $scope = null): ?array
    {
        if (!empty($scope) && $this->isValidScope($scope)) {
            return $this->tokens[$scope] ?? null;
        }

        return $this->tokens[$this->scope] ?? null;
    }

    public function setToken(string $scope, string $bearer, int $expires): bool
    {
        if (!$this->isValidScope($scope)) 
            return false;
        
        $this->tokens[$scope]['bearer'] = $bearer;
        $this->tokens[$scope]['expires'] = $expires;

        return true;
    }

    public function setTokens(array $tokens): void
    {
        foreach ($tokens as $scope => $token) {
            if (empty($token['bearer']) || empty($token['expires']))
                continue;

            $this->setToken($scope, $token['bearer'], $token['expires']);
        }
    }

    public function getTokens(): array
    {
        $tokens = [];

        foreach ($this->getValidScopes() as $scope) {
            $tokens[$scope] = [
                'bearer' => $this->getBearer($scope),
                'expires' => $this->getExpiresAt($scope),
            ];
        }

        return $tokens;
    }

    public function getBearer(?string $scope = null): ?string
    {
        return $this->getToken($scope)['bearer'] ?? null;
    }

    public function getExpiresAt(?string $scope = null): ?int
    {
        return $this->getToken($scope)['expires'] ?? null;
    }

    public function getExpiresIn(?string $scope = null): ?int
    {
        return ( $this->getToken($scope)['expires'] ?? time() ) - time();
    }

    public function isExpired(?string $scope = null): bool
    {
        return ( $this->getExpiresAt($scope) - time() ) < 0;
    }
}