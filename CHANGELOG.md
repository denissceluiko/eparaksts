# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.3.0] - 05.06.2026

### Added
- `ApiException` for non-2xx responses from the SignAPI signing endpoints
- `Signing::calculateDigest()`, `finalizeSigning()`, `addArchive()`, and `eSealCreate()` now throw `ApiException` on failure instead of silently returning null or partially-decoded error bodies

### Changed
- Minimum PHP version bumped from 8.2 to 8.4 (PHP 8.2 and 8.3 are EOL)
- `eSealCreate()` return type changed from `?array` to `array` (now throws on failure)
- `addArchive()` return type changed from untyped to `array` (now throws on failure)
- CI matrix updated to PHP 8.4 only

## [0.2.8]

### Added
- `Eparaksts::signBatch()` for signing multiple digests in a single server-side call
- `Eparaksts::CERT_QSEAL` constant and identity/certificate lookup support for qualified eSeals
- Age-gated identification scope constants: `SCOPE_IDENTIFICATION_WITH_AGE_14/16/18/21`
- `Signing::eSealCreate()` for file-based and smart-card eSeal signing
- `Signing::encryptSignKeyPassword()` for RSA-OAEP encryption of PFX passwords before passing them to `eSealCreate()`
- `Signing::addArchive()` for adding archive timestamps to signed documents
- `Storage::addDocumentDigest()` for adding pre-computed digests to a session
- `Storage::download()` `$asice` parameter for downloading `.edoc` documents as ASiC-E containers
- `Storage::upload()` `$filename` parameter to override the inferred filename
- Optional `HandlerStack` constructor parameter on both `Eparaksts` and `SignAPI` for injecting Guzzle middleware (testing, debugging)
- `Eparaksts::isAuthenticated()` for checking token validity before making requests
- `Configuration`, `Share`, and `Validation` sub-services on `SignAPI`
- Custom exception hierarchy: `EparakststException` (base) and `EncryptionException`
- PHPDoc on all public methods
- PHPStan static analysis at level 5 (`phpstan.neon`)
- PHP-CS-Fixer code style configuration (`.php-cs-fixer.php`)
- GitHub Actions CI workflow (test, lint, analyse)
- `composer.json` scripts: `test`, `fix`, `lint`, `analyse`
- Full test suite (94 tests across all classes)

### Changed
- `Eparaksts::filterIdentities()` visibility changed from `protected` to `public` to support multi-organisation qseal scenarios
- `Eparaksts::me()` corrected to use `GET` (was `POST`)
- `Eparaksts::authorize()` parameter renamed from `redirect_url` to `redirect_uri` to match the OAuth2 spec and eParaksts docs
- `Signing::calculateDigest()` endpoint corrected to `CalculateDigest` (capital C, capital D) to match the API
- `Signing::finalizeSigning()` list-array handling fixed (was wrapping an already-normalised list in an extra layer)
- `Storage::upload()` file detection changed from `ctype_print() && file_exists()` to `file_exists()` to support non-ASCII file paths
- `Storage::addDocumentDigest()` fixed to send a proper JSON body (was sending form data)
- `Storage::download()` fixed to append `?type=asice` as a query parameter rather than a path segment
- `Configuration::publicKey()` path corrected to `public/key` (removed leading slash that caused double-slash URLs)
- `Share::start()` now sends `Content-Type: application/json`
- `HasBasicAuthentication::encodeBasicAuth()` fixed to not URL-encode credentials before base64-encoding
- `SignAPI::request()` now sets `connect_timeout: 5`
- `Signing::encryptSignKeyPassword()` now throws `EncryptionException` instead of `\RuntimeException`
- `Signing::normalizeSessions()` simplified by removing redundant `is_array()` check after type narrowing
- `Storage::upload()` MIME type fallback corrected from `?? ''` to `?: ''` (`mime_content_type` returns `false`, not `null`)
- Algorithm validation in `Eparaksts::sign()` and `signBatch()` now uses `in_array` for an explicit allowlist

### Removed
- `error_log` debug call from `filterIdentities()`
