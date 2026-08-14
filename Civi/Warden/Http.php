<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Symfony\Component\HttpClient\HttpClient as SymfonyHttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * The HTTP client for discovery and JWKS.
 *
 * Overridable so tests never touch the network.
 */
final class Http {

  private static ?HttpClientInterface $override = NULL;

  public static function client(): HttpClientInterface {
    if (self::$override !== NULL) {
      return self::$override;
    }

    $options = [
      // Short and total. An identity provider that cannot answer discovery in
      // five seconds is down, and a login route that hangs is a denial of
      // service against the whole site, not just against SSO.
      'timeout' => 3.0,
      'max_duration' => 5.0,
      // The decorator validates only the URL passed to request(); Symfony
      // follows later hops internally. Refuse redirects so an HTTPS token or
      // JWKS request cannot be downgraded behind that boundary.
      'max_redirects' => 0,
      'headers' => ['Accept' => 'application/json'],
    ];
    $caFile = ini_get('openssl.cafile') ?: getenv('SSL_CERT_FILE') ?: getenv('CURL_CA_BUNDLE');
    if (is_string($caFile) && $caFile !== '' && is_readable($caFile)) {
      $options['cafile'] = $caFile;
    }

    return SymfonyHttpClient::create($options);
  }

  /**
   * Test seam. Passing NULL restores the real client.
   */
  public static function setClient(?HttpClientInterface $client): void {
    self::$override = $client;
  }

}
