<?php

namespace Dencel\Eparaksts\SignAPI\v1;

use Dencel\Eparaksts\Exception\ApiException;
use Dencel\Eparaksts\Exception\EncryptionException;

class Signing
{
    protected SignAPI $signAPI;

    public const ENDPOINT = '/api-sign/v1.0/';

    public function __construct(SignAPI $signAPI)
    {
        $this->signAPI = $signAPI;
    }

    /**
     * Calculate the digest to be signed for documents in the session.
     *
     * @param  array|string $sessions       Session ID string, or list of session ID strings.
     * @param  string       $certificate    PEM signing certificate (from Eparaksts::findCert()).
     * @param  bool         $signAsPDF      Sign as PAdES rather than XAdES/CAdES.
     * @param  bool|null    $createNewEdoc  Create a new .edoc container; null omits the parameter.
     * @return array        Digest response containing 'digestValue' and 'signatureAlgorithm'.
     * @throws ApiException On a non-2xx response.
     */
    public function calculateDigest(array|string $sessions, string $certificate, bool $signAsPDF = false, ?bool $createNewEdoc = null): array
    {
        $formattedSessions = $this->normalizeSessions($sessions);

        $body = [
            'sessions'      => $formattedSessions,
            'certificate'   => $certificate,
            'signAsPdf'     => $signAsPDF,
            'createNewEdoc' => $createNewEdoc,
        ];

        $body = array_filter($body);

        $path     = static::ENDPOINT . 'CalculateDigest';
        $response = $this->signAPI->post($path, [
            'headers' => [
                'content-type' => 'application/json',
            ],
            'body' => json_encode($body),
        ]);

        if ($response->getStatusCode() >= 300) {
            throw new ApiException('POST', $path, $response->getStatusCode(), $response->getBody()->getContents());
        }

        return json_decode($response->getBody()->getContents(), true);
    }

    /**
     * Submit the signed digest value(s) to finalize signing.
     *
     * Accepts three forms:
     * - finalizeSigning($cert, $sessionId, $signatureValue)
     * - finalizeSigning($cert, ['sessionId' => ..., 'signatureValue' => ...])
     * - finalizeSigning($cert, [['sessionId' => ..., 'signatureValue' => ...], ...])
     *
     * The signature must be base64-encoded.
     *
     * @param  string       $authCertificate Auth certificate (from Eparaksts::findCert()).
     * @param  array|string $sessions        Session ID, assoc array, or list of assoc arrays.
     * @param  string|null  $signature       Base64-encoded signature (only when $sessions is a string).
     * @return array        Response body.
     * @throws ApiException On a non-2xx response.
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

        $path     = static::ENDPOINT . 'finalizeSigning';
        $response = $this->signAPI->post($path, [
            'headers' => [
                'content-type' => 'application/json',
            ],
            'body' => json_encode($body),
        ]);

        if ($response->getStatusCode() >= 300) {
            throw new ApiException('POST', $path, $response->getStatusCode(), $response->getBody()->getContents());
        }

        return json_decode($response->getBody()->getContents(), true);
    }

    /**
     * Add an archive timestamp to signed documents in the session.
     *
     * @param  string       $authCertificate Auth certificate (from Eparaksts::findCert()).
     * @param  array|string $sessions        Session ID string or list of session ID strings.
     * @return array        Response body.
     * @throws ApiException On a non-2xx response.
     */
    public function addArchive(string $authCertificate, array|string $sessions): array
    {
        $formattedSessions = $this->normalizeSessions($sessions);

        $body = [
            'sessions'        => $formattedSessions,
            'authCertificate' => $authCertificate,
        ];

        $path     = static::ENDPOINT . 'addArchive';
        $response = $this->signAPI->post($path, [
            'headers' => [
                'content-type' => 'application/json',
            ],
            'body' => json_encode($body),
        ]);

        if ($response->getStatusCode() >= 300) {
            throw new ApiException('POST', $path, $response->getStatusCode(), $response->getBody()->getContents());
        }

        return json_decode($response->getBody()->getContents(), true);
    }

    /**
     * Create an eSeal using a PFX signing key (file-based or smart-card eSeal).
     *
     * Encrypt the PFX password with encryptSignKeyPassword() before passing it.
     *
     * @param  string|array $sessions         Session ID string or list of session ID strings.
     * @param  string       $authCertificate  Auth certificate (from Eparaksts::findCert()).
     * @param  string       $signKey          Base64-encoded PFX file contents.
     * @param  string       $signKeyPassword  RSA-OAEP encrypted PFX password (from encryptSignKeyPassword()).
     * @param  bool         $signAsPDF        Sign as PAdES rather than XAdES/CAdES.
     * @param  bool         $createNewEdoc    Create a new .edoc container.
     * @return array        Response body.
     * @throws ApiException On a non-2xx response.
     */
    public function eSealCreate(
        string|array $sessions,
        string $authCertificate,
        string $signKey,
        string $signKeyPassword,
        bool $signAsPDF = false,
        bool $createNewEdoc = false
    ): array {
        $formattedSessions = $this->normalizeSessions($sessions);

        $body = [
            'sessions'        => $formattedSessions,
            'authCertificate' => $authCertificate,
            'signKey'         => $signKey,
            'signKeyPassword' => $signKeyPassword,
            'signAsPdf'       => $signAsPDF,
            'createNewEdoc'   => $createNewEdoc,
        ];

        $path     = static::ENDPOINT . 'eSealCreate';
        $response = $this->signAPI->post($path, [
            'headers' => [
                'content-type' => 'application/json',
            ],
            'body' => json_encode($body),
        ]);

        if ($response->getStatusCode() >= 300) {
            throw new ApiException('POST', $path, $response->getStatusCode(), $response->getBody()->getContents());
        }

        return json_decode($response->getBody()->getContents(), true);
    }

    /**
     * Encrypt a PFX password with the SignAPI RSA public key (OAEP padding) for use in eSealCreate().
     *
     * @param  string $password Plaintext PFX password.
     * @return string Base64-encoded encrypted password.
     * @throws EncryptionException If encryption fails.
     */
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
