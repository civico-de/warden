<?php

declare(strict_types = 1);

namespace Civi\Warden;

use DigitalCz\OpenIDConnect\BackChannelLogout\LogoutToken;
use DigitalCz\OpenIDConnect\BackChannelLogout\LogoutTokenValidator;
use DigitalCz\OpenIDConnect\Exception\InvalidTokenException;

/**
 * Retry logout-token validation once after a controlled unknown-kid refresh.
 */
final class RefreshingLogoutTokenValidator implements LogoutTokenValidator {

  public function __construct(
    private readonly LogoutTokenValidator $inner,
    private readonly RefreshableJwksLoader $keys,
    private readonly string $jwksUri,
  ) {}

  public function validate(#[\SensitiveParameter] LogoutToken $token): void {
    try {
      $this->inner->validate($token);
    }
    catch (InvalidTokenException $original) {
      try {
        $refreshed = $this->keys->refreshForUnknownKid($this->jwksUri, (string) $token);
      }
      catch (\Throwable) {
        throw $original;
      }
      if (!$refreshed) {
        throw $original;
      }
      $this->inner->validate($token);
    }
  }

}
