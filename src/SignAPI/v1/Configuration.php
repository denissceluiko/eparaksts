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

    /**
     * Get the client configuration from the API.
     *
     * @param  string|null        $key Return only this key; returns the full array when null.
     * @return array|string|null  Config value, full config array, or null if the key is missing or the response is empty.
     */
    public function get(?string $key = null): null|array|string
    {
        $response = $this->signAPI->get(static::ENDPOINT);
        $data     = json_decode($response->getBody()->getContents(), true);

        if (empty($data)) {
            return null;
        }

        return empty($key) ? $data : ($data[$key] ?? null);
    }

    /**
     * Get the SignAPI RSA public key used to encrypt eSeal PFX passwords.
     *
     * @return array|null Array containing 'publicKey' (PEM string), or null on failure.
     */
    public function publicKey(): ?array
    {
        $response = $this->signAPI->get(static::ENDPOINT . 'public/key');
        return json_decode($response->getBody()->getContents(), true);
    }
}
