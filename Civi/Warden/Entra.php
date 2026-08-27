<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * Microsoft Entra ID's tenant-specific OIDC profile.
 *
 * Warden intentionally keeps Entra on the ordinary OIDC protocol path. This
 * helper only identifies the authority shape that needs provider-specific
 * operator guidance; token validation remains owned by the OIDC library.
 */
final class Entra {

  public const AUTHORITY_HOST = 'login.microsoftonline.com';
  public const ROLE_CLAIM = 'roles';

  /**
   * Build the exact issuer used by Entra v2 ID tokens for one tenant.
   *
   * @throws \InvalidArgumentException
   */
  public static function issuer(string $tenantId): string {
    if (!self::validTenantId($tenantId)) {
      throw new \InvalidArgumentException('An Entra tenant ID must be a GUID.');
    }

    return 'https://' . self::AUTHORITY_HOST . '/' . strtolower($tenantId) . '/v2.0';
  }

  /**
   * Does this issuer point at Microsoft's public-cloud authority?
   */
  public static function matches(string $issuer): bool {
    $host = parse_url($issuer, PHP_URL_HOST);

    return is_string($host) && strcasecmp($host, self::AUTHORITY_HOST) === 0;
  }

  /**
   * The tenant GUID when the issuer is the supported single-tenant v2 shape.
   */
  public static function tenantId(string $issuer): ?string {
    $guid = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
    $pattern = '#^https://' . preg_quote(self::AUTHORITY_HOST, '#') . '/(' . $guid . ')/v2[.]0$#i';
    if (preg_match($pattern, $issuer, $matches) !== 1) {
      return NULL;
    }

    return strtolower($matches[1] ?? '');
  }

  private static function validTenantId(string $tenantId): bool {
    return (
      preg_match(
        '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i',
        $tenantId,
      ) === 1
    );
  }

}
