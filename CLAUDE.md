# eparaksts — PHP client library

PHP library for integrating with the Latvian **eParaksts** e-signature and identity platform.  
Namespace: `Dencel\Eparaksts`. Requires PHP ≥ 8.2, Guzzle 7.

## Two distinct APIs, two distinct classes

| Class | Host | Purpose |
|---|---|---|
| `Eparaksts` | `eidas.eparaksts.lv` | OAuth2 authentication, user identity, server-side signing |
| `SignAPI\v1\SignAPI` | `signapi.eparaksts.lv` | Document upload, session management, sealing, validation |

`SignAPI` uses `eidas.eparaksts.lv` only for the OAuth token endpoint.

---

## Eparaksts class (`src/Eparaksts.php`)

### Construction
```php
$e = new Eparaksts($clientId, $clientSecret, $host = 'https://eidas.eparaksts.lv', $handlerStack = null);
```

### OAuth flow
1. Build authorization URL — redirect the user's browser here:
   ```php
   $url = $e->authorize(Eparaksts::SCOPE_IDENTIFICATION, $state, $redirectUri);
   // optional extra params via 4th arg: ['acr_values' => ..., 'ui_locales' => 'lv', ...]
   ```
2. Exchange the returned `code` for a token:
   ```php
   $token = $e->requestToken(Eparaksts::GRANT_AUTHORIZATION_CODE, ['code' => $code, 'redirect_uri' => $uri]);
   ```
3. Fetch user identity:
   ```php
   $user = $e->me();  // returns decoded JSON; uses the current scope's token
   ```
4. Log out:
   ```php
   $url = $e->logout($redirectUri);  // redirect user's browser here
   ```

### Scopes
```
SCOPE_IDENTIFICATION             urn:lvrtc:fpeil:aa
SCOPE_IDENTIFICATION_WITH_AGE    urn:lvrtc:fpeil:aa:age   (verify age; use age-specific variants below)
SCOPE_IDENTIFICATION_WITH_AGE_14 urn:lvrtc:fpeil:aa:age_14
SCOPE_IDENTIFICATION_WITH_AGE_16 urn:lvrtc:fpeil:aa:age_16
SCOPE_IDENTIFICATION_WITH_AGE_18 urn:lvrtc:fpeil:aa:age_18
SCOPE_IDENTIFICATION_WITH_AGE_21 urn:lvrtc:fpeil:aa:age_21
SCOPE_SIGNING_IDENTITY           urn:safelayer:eidas:sign:identity:profile
SCOPE_SIGNATURE                  urn:safelayer:eidas:sign:identity:use:server
SCOPE_SIGNAPI                    urn:safelayer:eidas:oauth:token:introspect
```

### Certificate types and identity lookup
`me()` returns a `sign_identities` array. Use `findIdentity()` / `findCert()` to locate the right one:

```php
$identities = $user['sign_identities'];
$cert = $e->findCert(Eparaksts::CERT_MOBILEID_SIGN, $identities);  // PEM string
```

| Constant | Matches |
|---|---|
| `CERT_MOBILEID_AUTH` | Mobile-ID authentication certificate |
| `CERT_MOBILEID_SIGN` | Mobile-ID signing certificate |
| `CERT_SIGNING` | Server-side signing identity (serverid) |
| `CERT_QSEAL` | Qualified electronic seal certificate (eZīmogs+ cloud) |

For qseal, a user may have **multiple** identities (one per organisation). `findIdentity()` returns the first; use `filterIdentities()` directly if you need all.

### Server-side signing
```php
// Single digest
$signature = $e->sign($digestBase64, 'rsa-sha256', $signIdentityId);
// Valid algorithms: rsa-sha1, rsa-sha256, rsa-sha384, rsa-sha512, ecdsa

// Batch
$results = $e->signBatch(
    [['digest_value' => $d1], ['digest_value' => $d2, 'signature_algorithm' => 'ecdsa']],
    'rsa-sha256',   // default algorithm for the batch
    $signIdentityId
);
```

### Token management
Tokens are stored per scope. The class is serializable (for PHP session storage):
```php
$_SESSION['ep'] = serialize($e);
$e = unserialize($_SESSION['ep']);
$e->isAuthenticated();  // checks bearer + expiry for the current scope
```

---

## SignAPI (`src/SignAPI/v1/`)

### Construction
```php
$api = new SignAPI($clientId, $clientSecret,
    $host      = 'https://signapi.eparaksts.lv/',
    $tokenHost = 'https://eidas.eparaksts.lv',
    $handlerStack = null
);
$api->freshToken();  // fetches a client_credentials token automatically
// or inject a previously obtained token:
$api->use($token);   // $token = ['bearer' => '...', 'expires' => timestamp]
```

### Typical document signing flow

```php
// 1. Start session
$session = $api->session()->start();
$sessionId = $session['sessionId'];

// 2. Upload document
$api->storage()->upload($sessionId, '/path/to/doc.pdf');

// 3. Calculate digest (using the user's signing certificate from Eparaksts::me())
$digest = $api->signing()->calculateDigest($sessionId, $signingCert);

// 4. Sign the digest via Eparaksts (server-side signing)
$signature = $eparaksts->sign($digest['digestValue'], $digest['signatureAlgorithm'], $signIdentityId);

// 5. Finalize
$api->signing()->finalizeSigning($authCert, $sessionId, base64_encode($signature));

// 6. Download signed document
$response = $api->storage()->download($sessionId, $fileId);
// or as ASiC-E container:
$response = $api->storage()->download($sessionId, $fileId, asice: true);

// 7. Validate (optional)
$api->validation()->validate($sessionId, $fileId);

// 8. Close session
$api->session()->close($sessionId);
```

### eZīmogs+ cloud (qualified eSeal) flow
Same as above but use `CERT_QSEAL` to retrieve the seal certificate from `me()` and pass it to `calculateDigest()`. Do **not** use `eSealCreate()` for this flow.

### File-based / smart-card eSeal
```php
// Encrypt the PFX password with the SignAPI public key before passing it
$encryptedPassword = $api->signing()->encryptSignKeyPassword($plaintextPassword);

$api->signing()->eSealCreate(
    $sessionId,
    $authCert,
    $pfxBase64,         // base64-encoded PFX file
    $encryptedPassword,
    signAsPDF: false,
    createNewEdoc: false
);
```

### Sub-services (all lazy-initialised singletons)
- `$api->session()` → `Session` — start / close
- `$api->storage()` → `Storage` — upload / list / download / delete / addDocumentDigest
- `$api->signing()` → `Signing` — calculateDigest / finalizeSigning / addArchive / eSealCreate / encryptSignKeyPassword
- `$api->validation()` → `Validation` — validate
- `$api->share()` → `Share` — share sessions with other persons
- `$api->configuration()` → `Configuration` — get / publicKey

---

## Debugging / testing

Both classes accept an optional `GuzzleHttp\HandlerStack`. Use Guzzle middleware to inspect or mock HTTP traffic:

```php
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;

$container = [];
$stack = HandlerStack::create(new MockHandler([new Response(200, [], '{}')]));
$stack->push(Middleware::history($container));

$api = new SignAPI('client', 'secret', handlerStack: $stack);
```

Run tests: `./vendor/bin/phpunit`

---

## Security notes

- **Serialization / SSRF** — `Eparaksts` implements `__serialize` / `__unserialize`. The `host` field is restored from the serialized payload and used directly in HTTP requests. Never deserialize an `Eparaksts` instance from untrusted input (e.g. a client-supplied cookie). Store serialized sessions server-side only (file, Redis, database).
- **Basic Auth** — credentials are transmitted via HTTP Basic Auth on the token endpoint. Always use HTTPS (the default hosts use it).

## Key implementation notes
- `Eparaksts::init()` is idempotent — it skips re-initialisation when credentials and host are unchanged.
- Token expiry is checked with `isExpired()` / `hasValidToken()` — always check before making a signed request in long-running processes.
- `finalizeSigning()` accepts three call forms: `($cert, $sessionId, $signature)`, `($cert, ['sessionId'=>..., 'signatureValue'=>...])`, or `($cert, [[$s1], [$s2], ...])`.
- Docs: https://developers.eparaksts.lv/docs/
