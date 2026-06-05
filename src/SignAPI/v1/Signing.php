<?php

namespace Dencel\Eparaksts\SignAPI\v1;

use Dencel\Eparaksts\Exception\EncryptionException;

class Signing
{
    protected SignAPI $signAPI;

    public const ENDPOINT = '/api-sign/v1.0/';

    public function __construct(SignAPI $signAPI)
    {
        $this->signAPI = $signAPI;
    }

    public function calculateDigest(array|string $sessions, string $certificate, bool $signAsPDF = false, ?bool $createNewEdoc = null): ?array
    {
        $formattedSessions = $this->normalizeSessions($sessions);

        $body = [
            'sessions'      => $formattedSessions,
            'certificate'   => $certificate,
            'signAsPdf'     => $signAsPDF,
            'createNewEdoc' => $createNewEdoc,
        ];

        $body = array_filter($body);

        $response = $this->signAPI->post(static::ENDPOINT . 'CalculateDigest', [
            'headers' => [
                'content-type' => 'application/json',
            ],
            'body' => json_encode($body),
        ]);

        return json_decode($response->getBody()->getContents(), true);
    }

    /**
     * Signatures have to be base64 encoded.
     *
     * Accepts signatures as:
     * - finalizeSigning($cert, $sessionId, $signature)
     * - finalizeSigning($cert, ["sessionId" => 'id', "signatureValue" => 'signature'])
     * - finalizeSigning($cert, [["sessionId" => 'id1', "signatureValue" => 'sig1'], ...])
     */
    public function finalizeSigning(string $authCertificate, array|string $sessions, ?string $signature = null): array
    {
        $formattedSessions = [];

        if (is_string($sessions) && is_string($signature)) {
            $formattedSessions[] = [
                'sessionId'      => $sessions,
                'signatureValue' => $signature,
            ];
        } elseif (is_array($sessions) && array_is_list($sessions)) {
            $formattedSessions = $sessions;
        } elseif (is_array($sessions)) {
            $formattedSessions[] = $sessions;
        }

        $body = [
            'sessionSignatureValues' => $formattedSessions,
            'authCertificate'        => $authCertificate,
        ];

        $response = $this->signAPI->post(static::ENDPOINT . 'finalizeSigning', [
            'headers' => [
                'content-type' => 'application/json',
            ],
            'body' => json_encode($body),
        ]);

        return json_decode($response->getBody()->getContents(), true);
    }

    public function addArchive(string $authCertificate, array|string $sessions)
    {
        $formattedSessions = $this->normalizeSessions($sessions);

        $body = [
            'sessions'        => $formattedSessions,
            'authCertificate' => $authCertificate,
        ];

        $response = $this->signAPI->post(static::ENDPOINT . 'addArchive', [
            'headers' => [
                'content-type' => 'application/json',
            ],
            'body' => json_encode($body),
        ]);

        return json_decode($response->getBody()->getContents(), true);
    }

    public function eSealCreate(
        string|array $sessions,
        string $authCertificate,
        string $signKey,
        string $signKeyPassword,
        bool $signAsPDF = false,
        bool $createNewEdoc = false
    ): ?array {
        $formattedSessions = $this->normalizeSessions($sessions);

        $body = [
            'sessions'        => $formattedSessions,
            'authCertificate' => $authCertificate,
            'signKey'         => $signKey,
            'signKeyPassword' => $signKeyPassword,
            'signAsPdf'       => $signAsPDF,
            'createNewEdoc'   => $createNewEdoc,
        ];

        $response = $this->signAPI->post(static::ENDPOINT . 'eSealCreate', [
            'headers' => [
                'content-type' => 'application/json',
            ],
            'body' => json_encode($body),
        ]);

        return json_decode($response->getBody()->getContents(), true);
    }

    public function encryptSignKeyPassword(string $password): string
    {
        $keyData = $this->signAPI->configuration()->publicKey();
        if (openssl_public_encrypt($password, $encrypted, $keyData['publicKey'], OPENSSL_PKCS1_OAEP_PADDING) === false) {
            throw new EncryptionException('Failed to encrypt sign key password: ' . openssl_error_string());
        }

        return base64_encode($encrypted);
    }

    protected function normalizeSessions(string|array $sessions): array
    {
        $normalized = [];

        if (is_string($sessions)) {
            $normalized[] = [
                'sessionId' => $sessions,
            ];
        } elseif (array_is_list($sessions)) {
            foreach ($sessions as $session) {
                $normalized[] = [
                    'sessionId' => $session,
                ];
            }
        } else {
            $normalized = $sessions;
        }

        return $normalized;
    }
}
