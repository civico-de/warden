<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * Everything the ID-token validator is allowed to accept, decided before a
 * token is seen. A value object so the rules are one constructor argument
 * rather than eight parameters that a caller can pass in the wrong order.
 */
final class ValidationPolicy {

  /**
   * @param string $issuer
   *   Compared to the `iss` claim byte for byte. This is the value from the
   *   DISCOVERY document, which discovery has already checked against the
   *   configured issuer — so a provider cannot widen its own identity.
   * @param string $clientId
   *   Must appear in `aud`, and must equal `azp` when that claim is present.
   * @param list<string> $allowedAlgorithms
   *   Exact, case-sensitive JWS algorithm names. Empty is a configuration
   *   error and rejects everything rather than allowing everything.
   * @param int $leeway
   *   Clock skew in seconds, applied to exp, iat and nbf in both directions.
   */
  public function __construct(
    public readonly string $issuer,
    public readonly string $clientId,
    public readonly array $allowedAlgorithms,
    public readonly int $leeway = 60,
  ) {}

  /**
   * @param list<string> $allowed
   */
  public static function create(string $issuer, string $clientId, array $allowed, int $leeway = 60): self {
    return new self($issuer, $clientId, $allowed, max(0, min(300, $leeway)));
  }

  /**
   * Parse the space-separated allow-list as stored on a provider row.
   *
   * @return list<string>
   */
  public static function parseAlgorithms(?string $raw): array {
    $parts = preg_split('/[\s,]+/', strtoupper(trim((string) $raw))) ?: [];

    return array_values(array_filter($parts, static fn (string $a): bool => $a !== ''));
  }

}
