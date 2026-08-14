<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * Claims from a verified OIDC Back-Channel Logout Token.
 */
final class LogoutTokenClaims {

  /**
   * @param array<string, mixed> $all
   */
  public function __construct(
    public readonly ?string $subject,
    public readonly ?string $sessionId,
    public readonly string $tokenId,
    public readonly array $all,
  ) {}

}
