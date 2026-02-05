<?php

namespace Dencel\Eparaksts;

use Dencel\Eparaksts\SignAPI\v1\SignAPI;
use Dencel\Eparaksts\Traits\CanRequestTokens;
use Dencel\Eparaksts\Traits\HasBasicAuthentication;
use Dencel\Eparaksts\Traits\HasScopedTokens;
use GuzzleHttp\Client;
use Psr\Http\Message\ResponseInterface;

class Eparaksts
{
    use CanRequestTokens;
    use HasBasicAuthentication;
    use HasScopedTokens;

    protected ?ResponseInterface $response = null;

    public const ACR_MOBILEID                   = 'urn:eparaksts:authentication:flow:mobileid';
    public const ACR_SC_PLUGIN                  = 'urn:eparaksts:authentication:flow:sc_plugin';
    public const ACR_MOBILEID_CROSS             = 'urn:eparaksts:authentication:flow:mobileid:cross-device';
    public const ACR_MOBILE_EID                 = 'urn:eparaksts:authentication:flow:mobile-eid';

    public const CERT_AUTHENTICATION            = 'authentication';
    public const CERT_SIGNING                   = 'signing';

    public function __construct(
        string $username, 
        string $password, 
        string $host = 'https://eidas.eparaksts.lv', 
    ) {
        $this->init($username, $password, $host);
    }

    public function init(string $username, string $password, string $host): void
    {
        if ($username === $this->username 
            && $password === $this->password 
            && $host === $this->host
        ) {
            return;
        }

        $this->setUsername($username);
        $this->setPassword($password);
        $this->setHost($host);
        $this->setTokenHost($host);
    }

    public function authorize(string $scope, string $state, string $redirect = '', ?array $data = []): ?string
    {
        $this->setScope($scope);

        $params = array_merge([
            'response_type' => 'code',
            'client_id' => $this->getUsername(),
            'scope' => $this->getScope(),
            'state' => $state,
            'redirect_url' => $redirect,
        ], $data);

        $query = http_build_query(array_filter($params));

        $uri = $this->host.'/trustedx-authserver/oauth/lvrtc-eipsign-as?'.$query;
        return $uri;
    }

    public function signAPIToken(): false|array
    {
        return $this->requestToken(
            static::GRANT_CLIENT_CREDENTIALS,
            ['scope' => static::SCOPE_SIGNAPI]
        );
    }

    public function me(?string $scope = null): array
    {
        $client = new Client();

        $this->response = $client->request('POST', $this->getHost().'/trustedx-resources/openid/v1/users/me', [
            'headers' => [
                'accept' => 'application/json',
                'authorization' => 'Bearer ' . $this->getBearer($scope),
            ],
            'connect_timeout' => 5,
            'http_errors' => false,
        ]);

        if ($this->response->getStatusCode() !== 200) 
            return [];

        return json_decode($this->response->getBody()->getContents(), true);
    }

    public function signIdentity(string $id): array
    {
        $client = new Client();

        $this->response = $client->request('GET', $this->getHost().'/trustedx-resources/esigp/v1/sign_identities/'.$id, [
            'headers' => [
                'accept' => 'application/json',
                'authorization' => 'Bearer ' . $this->getBearer(static::SCOPE_SIGNING_IDENTITY),
            ],
            'connect_timeout' => 5,
            'http_errors' => false,
        ]);

        if ($this->response->getStatusCode() !== 200) 
            return [];

        return json_decode($this->response->getBody()->getContents(), true);
    }

    public function sign(string $digest, string $signatureAlgo, string $signIdentity): ?string
    {
        $client = new Client();

        $signatureAlgo = ($signatureAlgo == 'ecdsa' ? 'ecdsa' : 'rsa-sha256');

        $body = [
            'digest_value' => $digest,
            'signature_algorithm' => $signatureAlgo,
            'sign_identity_id' => $signIdentity,
        ];

        $this->response = $client->request('POST', $this->getHost().'/trustedx-resources/esigp/v1/signatures/server/raw', [
            'headers' => [
                'Content-Type' => 'application/json',
                'authorization' => 'Bearer ' . $this->getBearer(static::SCOPE_SIGNATURE),
            ],
            'body' => json_encode($body),
            'connect_timeout' => 5,
            'http_errors' => false,
        ]);

        if ($this->response->getStatusCode() !== 200) {
            error_log('Signing failed with code: ' . $this->response->getStatusCode());
            return null;
        }

         return $this->response->getBody()->getContents();
    }

    public function getIdentity(string $type): ?array
    {
        if (!in_array($type, [
            static::CERT_AUTHENTICATION,
            static::CERT_SIGNING,
        ])) return null;

        if (!$this->isAuthenticated(static::SCOPE_SIGNING_IDENTITY))
            return null;

        $identities = $this->me(static::SCOPE_SIGNING_IDENTITY)['sign_identities'];

        if (empty($identities)) 
            return null;

        $types = [
            static::CERT_AUTHENTICATION => ['labels' => ['mobileid', 'x509:keyUsage:digitalSignature']],
            static::CERT_SIGNING => ['labels' => ['serverid']],
        ];

        $identities = $this->filterIdentities($identities, $types[$type]);
        $identity = $this->signIdentity($identities[0]['id']);

        return $identity['identity'];
    }

    protected function filterIdentities(array $identities, array $needles): array
    {
        $filtered = [];

        foreach ($identities as $identity) {
            foreach ($needles as $key => $value) {
                if (empty($identity[$key])){
                    continue;
                }

                if (is_string($value) && $identity[$key] !== $value) {
                    continue;
                }

                if (is_array($value) && count(array_intersect($identity[$key], $value)) != count($value)) {
                    continue;
                }

                $filtered[] = $identity;
            }

            if (empty($identity['status']) || $identity['status']['value'] != 'enabled'){
                continue;
            }

        }

        return $filtered;
    }

    public function getResponse(): ?ResponseInterface
    {
        return $this->response;
    }

    public function isAuthenticated(?string $scope = null): bool
    {
        return !empty($this->getToken($scope)['bearer']) && 
            $this->getToken($scope)['expires'] !== null && 
            !$this->isExpired($scope);
    }

    public function __serialize(): array
    {
        return [
            'tokens'   => $this->getTokens(),
            'scope'    => $this->getScope(),
            'host'     => $this->getHost(),
            'username' => $this->getUsername(),
            'password' => $this->getPassword(),
        ];
    }

    public function __unserialize(array $data): void
    {
        $this->init($data['username'], $data['password'], $data['host']);
        $this->setTokens($data['tokens']);
        $this->setScope($data['scope']);
    }
}