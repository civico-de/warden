<?php

declare(strict_types = 1);

namespace Civi\Warden;

use DigitalCz\OpenIDConnect\Client\IdToken;
use DigitalCz\OpenIDConnect\Client\IdTokenValidator;
use DigitalCz\OpenIDConnect\Exception\InvalidTokenException;

/**
 * Retry ID-token validation once after a controlled unknown-kid refresh.
 */
final class RefreshingIdTokenValidator implements IdTokenValidator {

  public function __construct(
    private readonly IdTokenValidator $inner,
    private readonly RefreshableJwksLoader $keys,
    private readonly string $jwksUri,
  ) {}

  public function validate(#[\SensitiveParameter] IdToken $token, ?string $nonce = NULL): void {
    try {
      $this->inner->validate($token, $nonce);
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
      $this->inner->validate($token, $nonce);
    }
  }

}
