<?php 

namespace Dencel\Eparaksts\SignAPI\v1;

class Configuration
{
    protected SignAPI $signAPI;

    public const ENDPOINT = '/api-config/v1.0/';

    public function __construct(SignAPI $signAPI)
    {
        $this->signAPI = $signAPI;
    }

    public function get(?string $key = null): null|array|string
    {
        $response = $this->signAPI->get(static::ENDPOINT);
        $data = json_decode($response->getBody()->getContents(), true);

        if (empty($data)) 
            return null;

        return empty($key) ? $data : ($data[$key] ?? null);
    }
    
    public function publicKey(): ?array
    {
        $response = $this->signAPI->get(static::ENDPOINT . '/public/key');
        return json_decode($response->getBody()->getContents(), true);
    }
}