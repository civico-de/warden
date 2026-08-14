<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * OIDC Discovery.
 *
 * Endpoints are fetched from the issuer, not typed in by an operator. That is
 * a security property and not only a convenience: hand-maintained endpoint
 * JSON is how a provider ends up still trusted after it moved its JWKS, and it
 * is why a hand-configured deployment has no `jwks_uri` to verify signatures
 * against in the first place.
 *
 * The one rule that makes discovery trustworthy: the document's own `issuer`
 * must equal the configured issuer exactly (OIDC Discovery 1.0 §4.3). Without
 * that check, anyone who can answer for the discovery URL can redirect the
 * whole flow to endpoints they control.
 */
final class Discovery {

  /**
   * @throws \CRM_Core_Exception
   */
  public static function forProvider(Provider $provider): DiscoveryDocument {
    $issuer = $provider->issuer;
    $url = $issuer . '/.well-known/openid-configuration';
    $cacheKey = self::cacheKey($provider);

    /** @var array<string, mixed> $document */
    $document = Cache::remember(
      $cacheKey,
      Cache::ttl(),
      static function () use ($url, $issuer): array {
        $document = Http::json($url);

        $declared = $document['issuer'] ?? NULL;
        if (!is_string($declared) || !hash_equals($issuer, rtrim($declared, '/'))) {
          throw new \CRM_Core_Exception(
            'warden: the discovery document at '
            . Http::redact($url)
            . ' declares a different issuer than the one configured. Refusing to use it.',
          );
        }

        return $document;
      },
    );

    return DiscoveryDocument::fromArray($document);
  }

  public static function cacheKey(Provider $provider): string {
    return 'discovery_' . $provider->id . '_' . substr(hash('sha256', $provider->issuer), 0, 16);
  }

  /**
   * Seconds since the discovery document was last fetched, or NULL if it has
   * never been fetched in this cache's lifetime.
   */
  public static function cacheAge(Provider $provider): ?int {
    $at = Cache::fetchedAt(self::cacheKey($provider));

    return $at === NULL ? NULL : max(0, time() - $at);
  }

}
