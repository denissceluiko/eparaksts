<?php 

namespace Dencel\Eparaksts\SignAPI\v1;

class Validation
{
    protected SignAPI $signAPI;

    public const ENDPOINT = '/api-validation/v1.0/';

    public function __construct(SignAPI $signAPI)
    {
        $this->signAPI = $signAPI;
    }

    public function validate(string $sessionId, string $fileId): ?array
    {
        $response = $this->signAPI->get(static::ENDPOINT . $sessionId . '/' . $fileId . '/validate');
        return json_decode($response->getBody()->getContents(), true);
    }
}