<?php

namespace Dencel\Eparaksts\Traits;

use GuzzleHttp\Client;

trait CanRequestTokens
{
    public const GRANT_CLIENT_CREDENTIALS       = 'client_credentials';
    public const GRANT_AUTHORIZATION_CODE       = 'authorization_code';

    public function requestToken(string $grant, array $params = []): false|array
    {
        $client = new Client();

        $response = $client->request('POST', $this->getTokenHost().'/trustedx-authserver/oauth/lvrtc-eipsign-as/token', [
            'headers' => [
                'accept' => 'application/json',
                'authorization' => 'Basic ' . $this->encodeBasicAuth(),
                'content-type' => 'application/x-www-form-urlencoded',
            ],
            'form_params' => array_merge([
                'grant_type' => $grant,
            ], $params),
            'connect_timeout' => 5,
            'http_errors' => false,
        ]);

        $responseArray = json_decode($response->getBody()->getContents(), true);

        if ($response->getStatusCode() !== 200) 
            return false;
        
        if (!empty($responseArray['error'])) {
            return false;
        }

        $this->setToken(
            $responseArray['scope'],
            $responseArray['access_token'], 
            time() + intval($responseArray['expires_in'])
        );

        return $this->getToken($responseArray['scope']);
    }
}