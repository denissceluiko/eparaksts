<?php

namespace Dencel\Eparaksts\SignAPI\v1;

use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\ResponseInterface;

class Storage
{
    protected SignAPI $signAPI;

    public const ENDPOINT = '/api-storage/v1.0/';

    public function __construct(SignAPI $signAPI)
    {
        $this->signAPI = $signAPI;
    }

    public function upload(string $sessionId, string $file): ?array
    {

        $contents = ctype_print($file) && file_exists($file) 
                    ? Utils::tryFopen($file, 'r') 
                    : $file;

        $filename = is_string($contents)
                    ? 'file.txt'
                    : substr($file, strrpos($file, '/'));

        $mimetype = is_string($contents)
                    ? 'text/plain'
                    : mime_content_type($filename) ?? '';

        $response = $this->signAPI->put(static::ENDPOINT . $sessionId . '/upload', [
            'multipart' => [
                [
                    'name' => 'file',
                    'filename' => $filename,
                    'contents' => $contents,
                    'headers' => [
                        'Content-Type' => $mimetype,
                    ],
                ]
            ],
        ]);

        if ($response->getStatusCode() !== 200) 
            return null;
    
        return json_decode($response->getBody()->getContents(), true);
    }

    public function list(string $sessionId): ?array
    {
        $response = $this->signAPI->get(static::ENDPOINT . $sessionId . '/list');

        if ($response->getStatusCode() !== 200) 
            return null;
    
        return json_decode($response->getBody()->getContents(), true);
    }

    public function download(string $sessionId, string $fileId): ResponseInterface
    {
        $response = $this->signAPI->get(static::ENDPOINT . $sessionId . '/' . $fileId);
        return $response;
    }

    public function delete(string $sessionId, string $fileId): ResponseInterface
    {
        $response = $this->signAPI->delete(static::ENDPOINT . $sessionId . '/' . $fileId);
        return $response;
    }

    public function addDocumentDigest(string $sessionId, array $files, string $signatureIndex = '0'): ?array
    {
        if (!array_is_list($files)) {
            $files = [
                [
                    'name' => $files['name'],
                    'digest' => $files['digest'],
                    'digest_algorithm' => $files['digest_algorithm'],
                ],
            ];
        }

        $response = $this->signAPI->post(static::ENDPOINT . $sessionId . '/addDocumentDigest', [
            'files' => $files,
            'signatureIndex' => $signatureIndex,
        ]);

        if ($response->getStatusCode() !== 200) 
            return null;
    
        return json_decode($response->getBody()->getContents(), true);
    }
}