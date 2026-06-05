# dencel/eparaksts

PHP 8.2+ client library for the [eParaksts](https://www.eparaksts.lv/) Latvian e-signature and identity platform.

## Installation

```bash
composer require dencel/eparaksts
```

## Two APIs

The library covers two distinct eParaksts services:

| Class | Host | Purpose |
|---|---|---|
| `Eparaksts` | `eidas.eparaksts.lv` | OAuth2 identity & remote signing |
| `SignAPI` | `signapi.eparaksts.lv` | Document session signing |

---

## Eparaksts — Identity & OAuth2

### Authorization code flow (web login)

```php
use Dencel\Eparaksts\Eparaksts;

$e = new Eparaksts('client-id', 'client-secret');

// 1. Redirect the user
$url = $e->authorize(Eparaksts::SCOPE_IDENTIFICATION, 'random-state', 'https://app.test/callback');
header('Location: ' . $url);

// 2. Handle the callback
$token = $e->requestToken(Eparaksts::GRANT_AUTHORIZATION_CODE, [
    'code'         => $_GET['code'],
    'redirect_uri' => 'https://app.test/callback',
]);

// 3. Fetch the authenticated user
$user = $e->me(Eparaksts::SCOPE_IDENTIFICATION);
```

### Client credentials flow (server-to-server)

```php
$token = $e->requestToken(Eparaksts::GRANT_CLIENT_CREDENTIALS, [
    'scope' => Eparaksts::SCOPE_SIGNATURE,
]);
```

### Scopes

| Constant | Value |
|---|---|
| `SCOPE_IDENTIFICATION` | `openid profile` |
| `SCOPE_SIGNATURE` | `openid sign` |
| `SCOPE_IDENTIFICATION_WITH_AGE_14/16/18/21` | age-gated identification |

### Remote signing

```php
// Get available identities for the authenticated user
$identities = $e->getSignIdentity(Eparaksts::SCOPE_SIGNATURE);

// Pick the signing certificate
$identity = $e->findIdentity(Eparaksts::CERT_MOBILEID_SIGN, $identities);
$cert     = $e->findCert(Eparaksts::CERT_MOBILEID_SIGN, $identities);

// Sign a digest
$signature = $e->sign($digest, 'rsa-sha256', $identity['id']);

// Batch sign multiple digests
$signatures = $e->signBatch([
    ['digest_value' => $digest1, 'document_name' => 'doc1.pdf'],
    ['digest_value' => $digest2, 'document_name' => 'doc2.pdf'],
], 'rsa-sha256', $identity['id']);
```

Certificate type constants: `CERT_MOBILEID_AUTH`, `CERT_MOBILEID_SIGN`, `CERT_SIGNING`, `CERT_QSEAL`.

### Session persistence

`Eparaksts` implements `__serialize`/`__unserialize` so it can be stored in the PHP session:

```php
$_SESSION['eparaksts'] = serialize($e);
$e = unserialize($_SESSION['eparaksts']);
```

### Logout

```php
$url = $e->logout('https://app.test/');
header('Location: ' . $url);
```

---

## SignAPI — Document signing sessions

```php
use Dencel\Eparaksts\SignAPI\v1\SignAPI;

$api = new SignAPI('client-id', 'client-secret');
$api->freshToken(); // fetches and stores a client_credentials token
```

### Signing flow

```php
// 1. Create a session
$session = $api->session()->start();
$sessionId = $session['sessionId'];

// 2. Upload document
$file = $api->storage()->upload($sessionId, '/path/to/doc.pdf');

// 3. Compute digest (pass auth certificate from Eparaksts::findCert())
$digest = $api->signing()->calculateDigest($sessionId, $authCert);

// 4. Sign the digest remotely (using Eparaksts client)
$signature = $eparaksts->sign($digest['digests'][0]['digest'], 'rsa-sha256', $identityId);

// 5. Finalize
$api->signing()->finalizeSigning($authCert, $sessionId, $signature);

// 6. Download signed document
$response = $api->storage()->download($sessionId, $file['fileId']);
// For .edoc documents only — download as ASiC-E container:
$response = $api->storage()->download($sessionId, $file['fileId'], asice: true);

// 7. Close session
$api->session()->close($sessionId);
```

### eSeal (server-side signing)

```php
$keyData = $api->configuration()->publicKey();

$encryptedPassword = $api->signing()->encryptSignKeyPassword('pfx-password');

$api->signing()->eSealCreate(
    sessions: $sessionId,
    authCertificate: $authCert,
    signKey: base64_encode(file_get_contents('seal.pfx')),
    signKeyPassword: $encryptedPassword,
);
```

### Batch signing (multiple sessions)

```php
$digest = $api->signing()->calculateDigest(['session-1', 'session-2'], $authCert);

$api->signing()->finalizeSigning($authCert, [
    ['sessionId' => 'session-1', 'signatureValue' => $sig1],
    ['sessionId' => 'session-2', 'signatureValue' => $sig2],
]);
```

### Other services

```php
// Sharing
$api->share()->start($sessionId, ['123456-12345']);
$api->share()->delete($sessionId);

// Validation
$api->validation()->validate($sessionId);

// Configuration
$maxFileSize = $api->configuration()->get('maxFileSize');
```

---

## Debugging

Inject a Guzzle `HandlerStack` with a history middleware to inspect all HTTP traffic:

```php
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;

$container = [];
$stack     = HandlerStack::create();
$stack->push(Middleware::history($container));

$e   = new Eparaksts('client', 'secret', handlerStack: $stack);
$api = new SignAPI('client', 'secret', handlerStack: $stack);

// After requests:
foreach ($container as $tx) {
    echo $tx['request']->getMethod() . ' ' . $tx['request']->getUri() . PHP_EOL;
}
```

---

## Requirements

- PHP 8.2+
- `ext-fileinfo`, `ext-openssl`

## License

MIT — see [LICENSE](LICENSE).
