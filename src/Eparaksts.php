<?php

namespace Dencel\Eparaksts;

use GuzzleHttp\Client;
use Psr\Http\Message\ResponseInterface;

class Eparaksts
{
    protected ?ResponseInterface $response = null;
    protected ?string $bearer = null;
    protected ?string $host = null;
    protected ?string $username = null;
    protected ?string $password = null;
    protected ?int $expires = null;

    public function __construct(string $username, string $password, string $host = 'https://eidas.eparaksts.lv')
    {
        $this->authenticate($username, $password, $host);
    }

    public function authenticate(string $username, string $password, string $host): bool
    {
        if ($username === $this->username 
            && $password === $this->password 
            && $host === $this->host
            && !empty($this->bearer)
            && $this->expires !== null
            && $this->expires > time()
        ) {
            return true;
        }

        $this->username = $username;
        $this->password = $password;
        $this->host = $host;

        return is_array($this->requestToken());
    }

    public function authorize(string $scope, string $redirect, string $state): ?bool
    {
        $client = new Client();

        $jar = new \GuzzleHttp\Cookie\CookieJar();
        $this->response = $client->request('GET', $this->host.'/trustedx-authserver/oauth/lvrtc-eipsign-as', [
            'headers' => [
                // 'accept' => 'application/json',
            ],
            'query' => [
                'respone_type' => 'code',
                'scope' => $scope,
                'client_id' => $this->username,
                'state' => $state,
                'redirect_url' => $redirect,
            ],
            'connect_timeout' => 5,
            'http_errors' => false,
            'cookies' => $jar,
            'allow_redirects' => true,  // First response will give a 302, second is 200
        ]);

        if ($this->response->getStatusCode() !== 200) 
            return null;

        return true;
    }
    
    protected function requestToken(): bool
    {
        $client = new Client();

        $this->response = $client->request('POST', $this->host.'/trustedx-authserver/oauth/lvrtc-eipsign-as/token', [
            'headers' => [
                'accept' => 'application/json',
                'authorization' => 'Basic ' . $this->encodeBasicAuth(),
                'content-type' => 'application/x-www-form-urlencoded',
            ],
            'form_params' => [
                'grant_type' => 'client_credentials',
                'scope' => 'urn:safelayer:eidas:oauth:token:introspect'
            ],
            'connect_timeout' => 5,
            'http_errors' => false,
        ]);

        if ($this->response->getStatusCode() !== 200) 
            return false;

        $responseArray = json_decode($this->response->getBody()->getContents(), true);
        $this->bearer = $responseArray['access_token'];
        $this->expires = time() + intval($responseArray['expires_in']);

        return true;
    }

    public function getBearer(): ?string
    {
        return $this->bearer;
    }

    public function getExpiry(): ?int
    {
        return ( $this->expires ?? time() ) - time();
    }

    public function getResponse(): ?ResponseInterface
    {
        return $this->response;
    }

    public function isAuthenticated(): bool
    {
        return !empty($this->bearer) && $this->expires !== null && ($this->expires - time()) > 0;
    }

    protected function encodeBasicAuth(): string
    {
        return base64_encode( urlencode($this->username) . ':' . urlencode($this->password));
    }
}