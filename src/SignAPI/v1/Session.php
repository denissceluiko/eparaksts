<?php

namespace Dencel\Eparaksts\SignAPI\v1;

class Session
{
    protected SignAPI $signAPI;

    public const ENDPOINT = '/api-session/v1.0/';

    public function __construct(SignAPI $signAPI)
    {
        $this->signAPI = $signAPI;
    }

    public function start(int $amount = 1): ?array
    {
        $response = $this->signAPI->get(static::ENDPOINT . 'start', [
            'query' => ['amount' => $amount],
        ]);

        if ($response->getStatusCode() !== 201) {
            return null;
        }

        return json_decode($response->getBody()->getContents(), true);
    }

    public function close(string $id): ?array
    {
        $response = $this->signAPI->get(static::ENDPOINT . $id . '/close');

        if ($response->getStatusCode() !== 200) 
            return null;
    
        return json_decode($response->getBody()->getContents(), true);
    }
}