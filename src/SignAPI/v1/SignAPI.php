<?php

namespace Dencel\Eparaksts\SignAPI\v1;

use Dencel\Eparaksts\Eparaksts;
use Dencel\Eparaksts\Traits\CanRequestTokens;
use Dencel\Eparaksts\Traits\HasBasicAuthentication;
use Dencel\Eparaksts\Traits\HasScopedTokens;
use GuzzleHttp\Client;
use Psr\Http\Message\ResponseInterface;

class SignAPI
{
    use CanRequestTokens;
    use HasBasicAuthentication;
    use HasScopedTokens;

    protected ?Client $client = null;
    protected ?Session $session = null;
    protected ?Storage $storage = null;
    protected ?Signing $signing = null;

    public function __construct(
        string $username, 
        string $password, 
        string $host = 'https://signapi.eparaksts.lv/', 
        string $tokenHost = 'https://eidas.eparaksts.lv'
    ) {
        $this->init($username, $password, $host, $tokenHost);
    }

    public function init(
        string $username, 
        string $password, 
        string $host, 
        string $tokenHost
    ): void {
        $this->setUsername($username);
        $this->setPassword($password);
        $this->setHost($host);
        $this->setTokenHost($tokenHost);
        $this->client = new Client();
        $this->setScope(static::SCOPE_SIGNAPI);
    }

    public function freshToken(): false|array
    {
        $token = $this->requestToken(
            static::GRANT_CLIENT_CREDENTIALS,
            ['scope' => static::SCOPE_SIGNAPI]
        );

        if ($token === false)
            return false;

        $this->use($token);
        return $token;
    }

    public function use(array $token): void
    {
        $this->setToken(
            static::SCOPE_SIGNAPI,
            $token['bearer'], 
            $token['expires']
        );

    }

    public function session(): Session
    {
        if ($this->session === null) {
            $this->session = new Session($this);
        }

        return $this->session;
    }

    public function storage(): Storage
    {
        if ($this->storage === null) {
            $this->storage = new Storage($this);
        }

        return $this->storage;
    }

    public function signing(): Signing
    {
        if ($this->signing === null) {
            $this->signing = new Signing($this);
        }

        return $this->signing;
    }

    public function get(string $path, array $options = []): ResponseInterface   
    {
        return $this->request('GET', $path, $options);
    }

    public function post(string $path, array $options = []): ResponseInterface   
    {
        return $this->request('POST', $path, $options);
    }

    public function put(string $path, array $options = []): ResponseInterface   
    {
        return $this->request('PUT', $path, $options);
    }

    public function delete(string $path, array $options = []): ResponseInterface
    {
        return $this->request('DELETE', $path, $options);
    }

    public function request(string $method, string $path, array $options = []): ResponseInterface   
    {
        $options = array_merge_recursive([
            'headers' => [
                'accept' => 'application/json',
                'authorization' => 'Bearer ' . $this->getBearer(),
            ],
            'http_errors' => false,
        ], $options);

        $response = $this->client->request($method, $this->formEndpointURI($path), $options);

        error_log($path . ': ' . $response->getStatusCode() . '; ' .json_encode($options));

        return $response;
    }

    protected function formEndpointURI(string $path): string
    {
        return rtrim($this->host, '/') . '/' . ltrim($path, '/');
    }
}