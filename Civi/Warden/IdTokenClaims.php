<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * Claims copied from an ID token after digitalcz/openid-connect has verified
 * its signature and required OIDC assertions.
 */
final class IdTokenClaims {

  /**
   * @param array<string, mixed> $all
   */
  public function __construct(
    public readonly string $subject,
    public readonly array $all,
  ) {}

  /**
   * Read a claim by dot path, e.g. `realm_access.roles`.
   */
  public function claim(string $path): mixed {
    return Claims::path($this->all, $path);
  }

  /**
   * The email claim, and whether the provider says it verified it.
   *
   * Returned as a pair on purpose — every caller that is tempted to use the
   * address has to look at the flag in the same expression.
   *
   * @return array{0: ?string, 1: bool}
   */
  public function email(): array {
    $email = $this->all['email'] ?? NULL;
    $verified = $this->all['email_verified'] ?? NULL;

    return [
      is_string($email) && $email !== '' ? $email : NULL,
      // Some providers send the string "true". Anything else is not verified.
      $verified === TRUE || $verified === 'true',
    ];
  }

}
