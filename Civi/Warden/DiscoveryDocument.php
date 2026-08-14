<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * The parts of an OIDC discovery document warden uses. Typed, so a provider
 * that omits a required endpoint fails at parse time with a sentence an
 * operator can act on, rather than as a NULL somewhere in the token exchange.
 */
final class DiscoveryDocument {

  /**
   * @param list<string> $signingAlgorithms
   *   `id_token_signing_alg_values_supported`. Empty when the provider does not
   *   advertise it, which is legal but unhelpful.
   */
  private function __construct(
    public readonly string $issuer,
    public readonly string $authorizationEndpoint,
    public readonly string $tokenEndpoint,
    public readonly string $jwksUri,
    public readonly ?string $endSessionEndpoint,
    public readonly array $signingAlgorithms,
    public readonly bool $supportsPkceS256,
  ) {}

  /**
   * @param array<string, mixed> $document
   *
   * @throws \CRM_Core_Exception
   */
  public static function fromArray(array $document): self {
    $methods = self::stringList($document, 'code_challenge_methods_supported');

    return new self(
      rtrim(self::required($document, 'issuer'), '/'),
      self::required($document, 'authorization_endpoint'),
      self::required($document, 'token_endpoint'),
      self::required($document, 'jwks_uri'),
      is_string($document['end_session_endpoint'] ?? NULL) ? $document['end_session_endpoint'] : NULL,
      self::stringList($document, 'id_token_signing_alg_values_supported'),
      // Absent means "not advertised". PKCE is sent regardless — a provider
      // that ignores an unknown parameter is no worse off, and one that
      // silently supports it is protected.
      $methods === [] || in_array('S256', $methods, TRUE),
    );
  }

  /**
   * @param array<string, mixed> $document
   *
   * @throws \CRM_Core_Exception
   */
  private static function required(array $document, string $key): string {
    $value = $document[$key] ?? NULL;
    if (!is_string($value) || $value === '') {
      throw new \CRM_Core_Exception(sprintf('warden: the discovery document has no usable "%s"', $key));
    }

    return $value;
  }

  /**
   * @param array<string, mixed> $document
   *
   * @return list<string>
   */
  private static function stringList(array $document, string $key): array {
    $value = $document[$key] ?? NULL;
    if (!is_array($value)) {
      return [];
    }

    $out = [];
    /** @var mixed $item */
    foreach ($value as $item) {
      if (is_string($item) && $item !== '') {
        $out[] = $item;
      }
    }

    return array_values(array_unique($out));
  }

}
