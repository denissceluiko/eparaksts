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

    /**
     * Upload a document to a session.
     *
     * Pass a file path to upload from disk, or a raw string for in-memory content.
     *
     * @param  string      $sessionId Session ID.
     * @param  string      $file      File path or raw file contents.
     * @param  string|null $filename  Override filename; inferred from path if omitted.
     * @return array|null  Response body containing 'fileId', or null on failure.
     */
    public function upload(string $sessionId, string $file, ?string $filename = null): ?array
    {

        $contents = file_exists($file)
                    ? Utils::tryFopen($file, 'r')
                    : $file;

        $filename = $filename ?? (
            is_string($contents)
                        ? 'file.txt'
                        : ltrim(substr($file, strrpos($file, '/')), '/')
        );

        $mimetype = is_string($contents)
                    ? 'text/plain'
                    : (mime_content_type($file) ?: '');

        $response = $this->signAPI->put(static::ENDPOINT . $sessionId . '/upload', [
            'multipart' => [
                [
                    'name'     => 'file',
                    'filename' => $filename,
                    'contents' => $contents,
                    'headers'  => [
                        'Content-Type' => $mimetype,
                    ],
                ],
            ],
        ]);

        if ($response->getStatusCode() !== 201) {
            return null;
        }

        return json_decode($response->getBody()->getContents(), true);
    }

    /**
     * List documents in a session.
     *
     * @param  string     $sessionId Session ID.
     * @return array|null List of file descriptors, or null on failure.
     */
    public function list(string $sessionId): ?array
    {
        $response = $this->signAPI->get(static::ENDPOINT . $sessionId . '/list');

        if ($response->getStatusCode() !== 200) {
            return null;
        }

        return json_decode($response->getBody()->getContents(), true);
    }

    /**
     * Download a document from a session.
     *
     * @param string $sessionId Session ID.
     * @param string $fileId    File ID.
     * @param bool   $asice     Download as ASiC-E container (only valid for .edoc documents).
     */
    public function download(string $sessionId, string $fileId, bool $asice = false): ResponseInterface
    {
        $options  = $asice ? ['query' => ['type' => 'asice']] : [];
        $response = $this->signAPI->get(static::ENDPOINT . $sessionId . '/' . $fileId, $options);
        return $response;
    }

    /**
     * Delete a document from a session.
     *
     * @param string $sessionId Session ID.
     * @param string $fileId    File ID.
     */
    public function delete(string $sessionId, string $fileId): ResponseInterface
    {
        $response = $this->signAPI->delete(static::ENDPOINT . $sessionId . '/' . $fileId);
        return $response;
    }

    /**
     * Add a pre-computed document digest to a session (for externally hashed documents).
     *
     * @param  string     $sessionId       Session ID.
     * @param  array      $files           Single file array or list of file arrays, each with 'name', 'digest', 'digest_algorithm'.
     * @param  string     $signatureIndex  Index of the signature slot (default '0').
     * @return array|null Response body, or null on failure.
     */
    public function addDocumentDigest(string $sessionId, array $files, string $signatureIndex = '0'): ?array
    {
        if (!array_is_list($files)) {
            $files = [
                [
                    'name'             => $files['name'],
                    'digest'           => $files['digest'],
                    'digest_algorithm' => $files['digest_algorithm'],
                ],
            ];
        }

        $response = $this->signAPI->post(static::ENDPOINT . $sessionId . '/addDocumentDigest', [
            'headers' => [
                'Content-Type' => 'application/json',
            ],
            'body' => json_encode([
                'files'          => $files,
                'signatureIndex' => $signatureIndex,
            ]),
        ]);

        if ($response->getStatusCode() !== 200) {
            return null;
        }

        return json_decode($response->getBody()->getContents(), true);
    }
}
