<?php

namespace Dencel\Eparaksts;

use Dencel\Eparaksts\Traits\CanRequestTokens;
use Dencel\Eparaksts\Traits\HasBasicAuthentication;
use Dencel\Eparaksts\Traits\HasScopedTokens;
use GuzzleHttp\HandlerStack;
use Psr\Http\Message\ResponseInterface;

class Eparaksts
{
    use CanRequestTokens;
    use HasBasicAuthentication;
    use HasScopedTokens;

    protected ?ResponseInterface $response = null;

    public const ACR_MOBILEID       = 'urn:eparaksts:authentication:flow:mobileid';
    public const ACR_SC_PLUGIN      = 'urn:eparaksts:authentication:flow:sc_plugin';
    public const ACR_MOBILEID_CROSS = 'urn:eparaksts:authentication:flow:mobileid:cross-device';
    public const ACR_MOBILE_EID     = 'urn:eparaksts:authentication:flow:mobile-eid';

    public const CERT_MOBILEID_AUTH = 'mobileid:auth';
    public const CERT_MOBILEID_SIGN = 'mobileid:sign';
    public const CERT_SIGNING       = 'signing';
    public const CERT_QSEAL         = 'qseal';

    public function __construct(
        string $username,
        string $password,
        string $host = 'https://eidas.eparaksts.lv',
        ?HandlerStack $handlerStack = null,
    ) {
        $this->handlerStack = $handlerStack;
        $this->init($username, $password, $host);
    }

    public function init(string $username, string $password, string $host): void
    {
        if ($username    === $this->username
            && $password === $this->password
            && $host     === $this->host
        ) {
            return;
        }

        $this->setUsername($username);
        $this->setPassword($password);
        $this->setHost($host);
        $this->setTokenHost($host);
    }

    /**
     * Build the authorization URL to redirect the user's browser to.
     *
     * @param string $scope One of the SCOPE_* constants.
     * @param string $state Random CSRF token; verify on callback.
     * @param string $redirect Callback URL registered with eParaksts.
     * @param array|null $data Extra query params (e.g. ['acr_values' => ..., 'ui_locales' => 'lv']).
     * @return string Authorization URL.
     */
    public function authorize(string $scope, string $state, string $redirect = '', ?array $data = []): ?string
    {
        $this->setScope($scope);

        $params = array_merge([
            'response_type' => 'code',
            'client_id'     => $this->getUsername(),
            'scope'         => $this->getScope(),
            'state'         => $state,
            'redirect_uri'  => $redirect,
        ], $data);

        $query = http_build_query(array_filter($params));

        $uri = $this->host . '/trustedx-authserver/oauth/lvrtc-eipsign-as?' . $query;
        return $uri;
    }

    /**
     * Obtain a client_credentials token scoped to SCOPE_SIGNAPI for use with SignAPI.
     *
     * @return false|array Token array with 'bearer' and 'expires', or false on failure.
     */
    public function signAPIToken(): false|array
    {
        return $this->requestToken(
            static::GRANT_CLIENT_CREDENTIALS,
            ['scope' => static::SCOPE_SIGNAPI]
        );
    }

    /**
     * Build the logout URL to redirect the user's browser to.
     *
     * @param string $redirect URL to redirect to after logout.
     * @return string Logout URL.
     */
    public function logout(string $redirect = ''): ?string
    {
        $query = http_build_query([
            'redirect_uri' => $redirect,
        ]);

        return $this->host . '/trustedx-authserver/lvrtc-eipsign-idp/logout?' . $query;
    }

    /**
     * Fetch the authenticated user's profile and sign_identities.
     *
     * @param string|null $scope Scope whose bearer token to use; defaults to the current scope.
     * @return array Decoded JSON body, or empty array on failure.
     */
    public function me(?string $scope = null): array
    {
        $client = $this->createClient();

        $this->response = $client->request('GET', $this->getHost() . '/trustedx-resources/openid/v1/users/me', [
            'headers' => [
                'accept'        => 'application/json',
                'authorization' => 'Bearer ' . $this->getBearer($scope),
            ],
            'connect_timeout' => 5,
            'http_errors'     => false,
        ]);

        if ($this->response->getStatusCode() !== 200) {
            return [];
        }

        return json_decode($this->response->getBody()->getContents(), true);
    }

    /**
     * Fetch a single sign identity by its ID.
     *
     * @param string $id Sign identity ID.
     * @return array Decoded JSON body, or empty array on failure.
     */
    public function getSignIdentity(string $id): array
    {
        $client = $this->createClient();

        $this->response = $client->request('GET', $this->getHost() . '/trustedx-resources/esigp/v1/sign_identities/' . $id, [
            'headers' => [
                'accept'        => 'application/json',
                'authorization' => 'Bearer ' . $this->getBearer(static::SCOPE_SIGNING_IDENTITY),
            ],
            'connect_timeout' => 5,
            'http_errors'     => false,
        ]);

        if ($this->response->getStatusCode() !== 200) {
            return [];
        }

        return json_decode($this->response->getBody()->getContents(), true);
    }

    /**
     * Sign a single digest server-side.
     *
     * @param string $digest Base64-encoded digest value.
     * @param string $signatureAlgo One of: rsa-sha1, rsa-sha256, rsa-sha384, rsa-sha512, ecdsa.
     * @param string $signIdentity Sign identity ID from findIdentity()['id'].
     * @return string|null Base64-encoded signature, or null on invalid algorithm or request failure.
     */
    public function sign(string $digest, string $signatureAlgo, string $signIdentity): ?string
    {
        if (!in_array($signatureAlgo, ['rsa-sha1', 'rsa-sha256', 'rsa-sha384', 'rsa-sha512', 'ecdsa'])) {
            return null;
        }

        $client = $this->createClient();

        $body = [
            'digest_value'        => $digest,
            'signature_algorithm' => $signatureAlgo,
            'sign_identity_id'    => $signIdentity,
        ];

        $this->response = $client->request('POST', $this->getHost() . '/trustedx-resources/esigp/v1/signatures/server/raw', [
            'headers' => [
                'Content-Type'  => 'application/json',
                'authorization' => 'Bearer ' . $this->getBearer(static::SCOPE_SIGNATURE),
            ],
            'body'            => json_encode($body),
            'connect_timeout' => 5,
            'http_errors'     => false,
        ]);

        if ($this->response->getStatusCode() !== 200) {
            return null;
        }

        return $this->response->getBody()->getContents();
    }

    /**
     * Sign multiple digests in a single server-side batch call.
     *
     * Each request must contain a 'digest_value' key; 'signature_algorithm' is optional per-item.
     *
     * @param array $requests List of digest request arrays.
     * @param string $signatureAlgo Default algorithm for the batch.
     * @param string $signIdentity Sign identity ID from findIdentity()['id'].
     * @return array|null List of signature results, or null on invalid algorithm or request failure.
     */
    public function signBatch(array $requests, string $signatureAlgo, string $signIdentity): ?array
    {
        if (!in_array($signatureAlgo, ['rsa-sha1', 'rsa-sha256', 'rsa-sha384', 'rsa-sha512', 'ecdsa'])) {
            return null;
        }

        $client = $this->createClient();

        $body = [
            'sign_identity_id'    => $signIdentity,
            'signature_algorithm' => $signatureAlgo,
            'requests'            => $requests,
        ];

        $this->response = $client->request('POST', $this->getHost() . '/trustedx-resources/esigp/v1/signatures/server/raw/batch', [
            'headers' => [
                'Content-Type'  => 'application/json',
                'authorization' => 'Bearer ' . $this->getBearer(static::SCOPE_SIGNATURE),
            ],
            'body'            => json_encode($body),
            'connect_timeout' => 5,
            'http_errors'     => false,
        ]);

        if ($this->response->getStatusCode() !== 200) {
            return null;
        }

        return json_decode($this->response->getBody()->getContents(), true);
    }

    /**
     * Return the first enabled identity matching $type from the sign_identities list.
     *
     * @param string $type One of the CERT_* constants.
     * @param array $identities The sign_identities array from me().
     * @return array|null First matching identity, or null if none found or type is unknown.
     */
    public function findIdentity(string $type, array $identities): ?array
    {
        if (!in_array($type, [
            static::CERT_MOBILEID_AUTH,
            static::CERT_MOBILEID_SIGN,
            static::CERT_SIGNING,
            static::CERT_QSEAL,
        ])) {
            return null;
        }

        $types = [
            static::CERT_MOBILEID_AUTH => ['labels' => ['mobileid', 'x509:keyUsage:digitalSignature'],  'description' => 'eparaksts:mobileid:auth'],
            static::CERT_MOBILEID_SIGN => ['labels' => ['mobileid', 'x509:keyUsage:contentCommitment'], 'description' => 'eparaksts:mobileid:sign'],
            static::CERT_SIGNING       => ['labels' => ['serverid']],
            static::CERT_QSEAL         => ['labels' => ['qsealc', 'x509:keyUsage:contentCommitment'],   'description' => 'eparaksts:qsealc:sign'],
        ];

        $identities = $this->filterIdentities($identities, $types[$type]);

        if (empty($identities)) {
            return null;
        }

        return $identities[0];
    }

    /**
     * Return the PEM certificate for the first enabled identity matching $type.
     *
     * @param string $type One of the CERT_* constants.
     * @param array $identities The sign_identities array from me().
     * @return string|null PEM certificate string, or null if not found.
     */
    public function findCert(string $type, array $identities): ?string
    {
        $identity = $this->findIdentity($type, $identities);
        return !is_null($identity) ? $identity['details']['certificate'] : null;
    }

    /**
     * Filter sign_identities to those that are enabled and match all given needle key/value pairs.
     *
     * String needle values require an exact match; array needle values require all elements to be present.
     * Use this directly when you need all matching identities (e.g. qseal with multiple organisations).
     *
     * @param array $identities The sign_identities array from me().
     * @param array $needles Map of identity field names to required values.
     * @return array Matching enabled identities.
     */
    public function filterIdentities(array $identities, array $needles): array
    {
        $filtered = [];

        foreach ($identities as $identity) {
            if (empty($identity['status']) || $identity['status']['value'] != 'enabled') {
                continue;
            }

            foreach ($needles as $key => $value) {
                if (empty($identity[$key])) {
                    continue 2;
                }

                if (is_string($value) && $identity[$key] !== $value) {
                    continue 2;
                }

                if (is_array($value) && count(array_intersect($identity[$key], $value)) != count($value)) {
                    continue 2;
                }
            }

            $filtered[] = $identity;
        }

        return $filtered;
    }

    /** @return ResponseInterface|null The raw response from the last API call. */
    public function getResponse(): ?ResponseInterface
    {
        return $this->response;
    }

    /**
     * Check whether the current (or given) scope has a valid, non-expired bearer token.
     *
     * @param string|null $scope Scope to check; defaults to the current scope.
     */
    public function isAuthenticated(?string $scope = null): bool
    {
        return !empty($this->getToken($scope)['bearer']) && $this->getToken($scope)['expires'] !== null && !$this->isExpired($scope);
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
