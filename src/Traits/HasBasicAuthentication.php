<?php

namespace Dencel\Eparaksts\Traits;

trait HasBasicAuthentication
{
    protected ?string $host = null;
    protected ?string $tokenHost = null;
    protected ?string $username = null;
    protected ?string $password = null;

    public function getHost(): string
    {
        return $this->host;
    }

    public function setHost(string $host): void
    {
        $this->host = $host;
    }

    
    public function getTokenHost(): string
    {
        return $this->tokenHost;
    }

    public function setTokenHost(string $tokenHost): void
    {
        $this->tokenHost = $tokenHost;
    }

    public function getUsername(): string
    {
        return $this->username;
    }

    public function setUsername(string $username): void
    {
        $this->username = $username;
    }
    
    public function getPassword(): string
    {
        return $this->password;
    }

    public function setPassword(string $password): void
    {
        $this->password = $password;
    }

    public function encodeBasicAuth(): string
    {
        return base64_encode( urlencode($this->username) . ':' . urlencode($this->password));
    }
}