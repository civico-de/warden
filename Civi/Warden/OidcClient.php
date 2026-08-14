<?php

declare(strict_types = 1);

namespace Civi\Warden;

use DigitalCz\OpenIDConnect\BackChannelLogout\BackChannelLogoutHandler;
use DigitalCz\OpenIDConnect\BackChannelLogout\JwtLogoutTokenValidator;
use DigitalCz\OpenIDConnect\Client\AuthenticationMethod;
use DigitalCz\OpenIDConnect\Client\AuthorizationCode;
use DigitalCz\OpenIDConnect\Client\JwtIdTokenValidator;
use DigitalCz\OpenIDConnect\Config\ClientMetadata;
use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use DigitalCz\OpenIDConnect\Config\StaticConfig;
use DigitalCz\OpenIDConnect\Discovery\HttpDiscoverer;
use DigitalCz\OpenIDConnect\Discovery\HttpJwksLoader;
use DigitalCz\OpenIDConnect\Exception\DiscoveryException;
use DigitalCz\OpenIDConnect\Util\PkceMethod;
use DigitalCz\OpenIDConnect\Util\SecureHttpClient;
use DigitalCz\OpenIDConnect\Util\SecureUrl;
use DigitalCz\OpenIDConnect\Util\SimpleClock;

// @mago-expect lint:cyclomatic-complexity
// This is the protocol-library boundary: keeping construction, secure
// discovery and algorithm restriction together makes the trust policy visible.
/**
 * The narrow boundary between Warden and digitalcz/openid-connect.
 *
 * The library owns the OIDC protocol. Warden supplies provider settings,
 * CiviCRM cache/HTTP services and its configurable clock tolerance.
 */
final class OidcClient {

  private readonly AuthorizationCode $authorizationCode;
  private readonly BackChannelLogoutHandler $backChannelLogout;

  private function __construct(
    private readonly Provider $provider,
    private readonly IssuerMetadata $metadata,
  ) {
    $http = new SecureHttpClient(Http::client());
    $clock = new SimpleClock();
    $client = new ClientMetadata(
      clientId: $provider->clientId,
      clientSecret: $provider->clientSecret !== '' ? $provider->clientSecret : NULL,
      redirectUri: RedirectUri::get(),
      defaultScopes: preg_split('/\s+/', trim($provider->scopes)) ?: ['openid'],
      authenticationMethod: $provider->clientSecret !== ''
        ? AuthenticationMethod::ClientSecretBasic
        : AuthenticationMethod::None,
      pkceMethod: PkceMethod::S256,
      clock: $clock,
    );
    $config = new StaticConfig(self::restrictAlgorithms($metadata, $provider), $client);
    $cache = new OidcCache();
    $cacheSecret = Value::str(\CRM_Utils_Constant::value('CIVICRM_SITE_KEY'), 'warden');
    $keys = new RefreshableJwksLoader(
      new HttpJwksLoader($http),
      $cache,
      Cache::ttl(),
      $cacheSecret,
    );
    $leeway = max(0, min(300, Value::int(\Civi::settings()->get('warden_clock_leeway'), 60)));
    $jwksUri = $metadata->jwksUri();
    $idTokenValidator = new JwtIdTokenValidator($config, $keys, $clock, $leeway);
    $logoutTokenValidator = new JwtLogoutTokenValidator($config, $keys, $clock, $leeway);

    $this->authorizationCode = new AuthorizationCode(
      $config,
      $http,
      new RefreshingIdTokenValidator($idTokenValidator, $keys, $jwksUri),
    );
    $this->backChannelLogout = new BackChannelLogoutHandler(
      new RefreshingLogoutTokenValidator($logoutTokenValidator, $keys, $jwksUri),
    );
  }

  public static function forProvider(Provider $provider): self {
    return new self($provider, self::metadataFor($provider));
  }

  public function authorizationCode(): AuthorizationCode {
    return $this->authorizationCode;
  }

  public function backChannelLogout(): BackChannelLogoutHandler {
    return $this->backChannelLogout;
  }

  public function metadata(): IssuerMetadata {
    return $this->metadata;
  }

  /**
   * Resolve and persist discovery through CiviCRM's cache. Storing the plain
   * claims rather than a library object keeps the cache stable across package
   * upgrades.
   */
  public static function metadataFor(Provider $provider): IssuerMetadata {
    /** @var array<string, string|string[]|bool> $claims */
    $claims = Cache::remember(
      self::discoveryCacheKey($provider),
      Cache::ttl(),
      static function () use ($provider): array {
        $discoverer = new HttpDiscoverer(new SecureHttpClient(Http::client()));
        $metadata = $discoverer->discover($provider->issuer);

        // Resolve every endpoint needed by the supported flows now, so a
        // broken document fails as discovery rather than halfway through login.
        $discoveredIssuer = $metadata->issuer();
        if (!hash_equals($provider->issuer, $discoveredIssuer)) {
          throw new DiscoveryException(sprintf(
            'OIDC discovery issuer mismatch: expected "%s", got "%s".',
            $provider->issuer,
            $discoveredIssuer,
          ));
        }
        SecureUrl::requireSecure($metadata->authorizationEndpoint());
        SecureUrl::requireSecure($metadata->tokenEndpoint());
        SecureUrl::requireSecure($metadata->jwksUri());
        $endSessionEndpoint = $metadata->claims()['end_session_endpoint'] ?? NULL;
        if (is_string($endSessionEndpoint) && $endSessionEndpoint !== '') {
          SecureUrl::requireSecure($endSessionEndpoint);
        }

        return self::normalizeMetadataClaims($metadata->claims());
      },
    );

    return new IssuerMetadata($claims);
  }

  public static function discoveryCacheKey(Provider $provider): string {
    return 'discovery_' . $provider->id . '_' . substr(hash('sha256', $provider->issuer), 0, 16);
  }

  public static function discoveryCacheAge(Provider $provider): ?int {
    $at = Cache::fetchedAt(self::discoveryCacheKey($provider));

    return $at === NULL ? NULL : max(0, time() - $at);
  }

  /**
   * Load the same cached key set used for token verification, for health
   * checks that need to distinguish valid discovery from unusable keys.
   *
   * @return array{keys: non-empty-list<array<string, mixed>>}
   */
  public static function jwksFor(Provider $provider): array {
    $metadata = self::metadataFor($provider);
    $cacheSecret = Value::str(\CRM_Utils_Constant::value('CIVICRM_SITE_KEY'), 'warden');
    $loader = new RefreshableJwksLoader(
      new HttpJwksLoader(new SecureHttpClient(Http::client())),
      new OidcCache(),
      Cache::ttl(),
      $cacheSecret,
    );
    $keys = $loader->load($metadata->jwksUri());
    $keySet = $keys['keys'] ?? NULL;
    if (!is_array($keySet) || !array_is_list($keySet) || $keySet === []) {
      throw new \CRM_Core_Exception('warden: the provider key set contains no signing keys');
    }
    $normalizedKeySet = [];
    foreach ($keySet as $key) {
      if (!is_array($key)) {
        throw new \CRM_Core_Exception('warden: the provider key set contains an invalid signing key');
      }
      $normalizedKeySet[] = Value::row($key);
    }

    return ['keys' => $normalizedKeySet];
  }

  /**
   * Create a query-safe RP-initiated logout URL. digitalcz 1.4 always appends
   * `?`, which corrupts a legal end_session_endpoint that already has a query.
   *
   * @param array<string, string> $params
   */
  public function logoutUrl(array $params = []): string {
    $endpoint = $this->metadata->endSessionEndpoint();
    $params['client_id'] ??= $this->provider->clientId;
    $separator = str_contains($endpoint, '?') ? '&' : '?';

    return $endpoint . $separator . http_build_query($params);
  }

  private static function restrictAlgorithms(IssuerMetadata $metadata, Provider $provider): IssuerMetadata {
    $claims = self::normalizeMetadataClaims($metadata->claims());
    $advertised = $metadata->idTokenSigningAlgValuesSupported();
    $claims['id_token_signing_alg_values_supported'] = $advertised === []
      ? $provider->allowedAlgorithms
      : array_values(array_intersect($advertised, $provider->allowedAlgorithms));

    return new IssuerMetadata($claims);
  }

  /**
   * Keep only the value types accepted by IssuerMetadata. Discovery documents
   * may contain provider-specific JSON objects or numbers which the library
   * does not consume and cannot safely represent in this value object.
   *
   * @param array<mixed> $claims
   *
   * @return array<string, string|list<string>|bool>
   */
  private static function normalizeMetadataClaims(array $claims): array {
    $normalized = [];
    foreach ($claims as $name => $value) {
      if (!is_string($name)) {
        continue;
      }
      if (is_string($value) || is_bool($value)) {
        $normalized[$name] = $value;
        continue;
      }
      if (is_array($value) && array_is_list($value)) {
        $strings = Value::strings($value);
        if (count($strings) === count($value)) {
          $normalized[$name] = $strings;
        }
      }
    }

    return $normalized;
  }

}
