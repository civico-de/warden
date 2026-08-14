<?php

declare(strict_types = 1);

namespace Civi\Warden;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;

/**
 * The HTTP client for discovery and JWKS.
 *
 * Core has no shared client to borrow: `Civi::service('httpClient')` is
 * `CRM_Utils_HttpClient`, a thin curl wrapper with no timeout control and no
 * PSR-7 surface. Core itself just instantiates Guzzle where it needs one, and
 * so do we.
 *
 * Overridable so tests never touch the network.
 */
final class Http {

  private static ?ClientInterface $override = NULL;

  public static function client(): ClientInterface {
    return (
      self::$override ?? new Client([
        // Short and total. An identity provider that cannot answer discovery in
        // five seconds is down, and a login route that hangs is a denial of
        // service against the whole site, not just against SSO.
        'connect_timeout' => 3.0,
        'timeout' => 5.0,
        'http_errors' => TRUE,
        'headers' => ['Accept' => 'application/json'],
      ])
    );
  }

  /**
   * Fetch and decode a JSON document.
   *
   * @return array<string, mixed>
   *
   * @throws \CRM_Core_Exception
   */
  public static function json(string $url): array {
    if (!str_starts_with($url, 'https://')) {
      // The ID token's only transport-level protection is TLS on the endpoints
      // it was fetched from. http:// discovery would make every check below it
      // decorative.
      throw new \CRM_Core_Exception(sprintf('warden refuses to fetch %s over plain HTTP', self::redact($url)));
    }

    try {
      $response = self::client()->request('GET', $url);
    }
    catch (\Throwable $e) {
      throw new \CRM_Core_Exception(
        sprintf('warden could not reach %s: %s', self::redact($url), $e->getMessage()),
        0,
        [],
        $e,
      );
    }

    $decoded = json_decode((string) $response->getBody(), TRUE);
    if (!is_array($decoded)) {
      throw new \CRM_Core_Exception(sprintf('warden got a non-JSON response from %s', self::redact($url)));
    }

    /** @var array<string, mixed> $decoded */
    return $decoded;
  }

  /**
   * Strip any query string before a URL reaches a log or an error message —
   * discovery URLs do not carry secrets, but this is the one place every
   * outbound URL passes through, so the rule is enforced once.
   */
  public static function redact(string $url): string {
    return explode('?', $url)[0];
  }

  /**
   * Test seam. Passing NULL restores the real client.
   */
  public static function setClient(?ClientInterface $client): void {
    self::$override = $client;
  }

}
