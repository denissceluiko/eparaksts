<?php 

namespace Dencel\Eparaksts\SignAPI\v1;

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
        $formattedSessions = [];

        if (is_string($sessions)) {
            $formattedSessions[] = ['sessionId' => $sessions];
        } else {
            foreach ($sessions as $session) {
                $formattedSessions[] = ['sessionId' => $session];
            }
        }

        $body = [
            'sessions' => $formattedSessions,
            'certificate' => $certificate,
            'signAsPdf' => $signAsPDF,
            'createNewEdoc' => $createNewEdoc,
        ];

        $body = array_filter($body);

        $response = $this->signAPI->post(static::ENDPOINT . 'calculateDigest', [
            'body' => json_encode($body),
            'headers' => [
                'accept' => 'application/json',
                'content-type' => 'application/json',
            ],
        ]);

        return json_decode($response->getBody()->getContents(), true);
    }

    /**
     * Calls finalizeSigning endpoint.
     * 
     * Signatures have to be base64 encoded!!!!
     * 
     * Accepts signatures as: 
     * $session, $signature
     * ["sessionId" => 'id', "signatureValue" => 'signature']
     * [ ["sessionId" => 'id1', "signatureValue" => 'signature1'], ["sessionId" => 'id2', "signatureValue" => 'signature2'], ...]
     * 
     *
     * @param array|string $sessions
     * @param string|null $signature
     * @param string $authCertificate
     * @return void
     */
    public function finalizeSigning(string $authCertificate, array|string $sessions, ?string $signature = null): array
    {
        $formattedSessions = [];

        if (is_string($sessions) && is_string($signature)) {
            $formattedSessions[] = [
                "sessionId" => $sessions,
                "signatureValue" => $signature,
            ];
        } elseif (is_array($sessions) && !array_is_list($sessions)) {
            $formattedSessions[] = $sessions;
        }

        $body = [
            'sessionSignatureValues' => $formattedSessions,
            'authCertificate' => $authCertificate,
        ];

        $response = $this->signAPI->post(static::ENDPOINT . 'finalizeSigning', [
            'headers' => [
                'content-type' => 'application/json',
            ],
            'body' => json_encode($body),
        ]);

        return json_decode($response->getBody()->getContents(), true);
    }
}