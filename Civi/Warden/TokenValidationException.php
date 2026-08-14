<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * A rejected ID token.
 *
 * The `reason` is a stable machine code that lands in the audit trail and in
 * herald alerts; the message is for an operator reading the log. Neither ever
 * contains the token, a claim value or a key.
 */
final class TokenValidationException extends \RuntimeException {

  public const R_MALFORMED = 'malformed';
  public const R_ALG_NONE = 'alg_none';
  public const R_ALG_NOT_ALLOWED = 'alg_not_allowed';
  public const R_ALG_UNSUPPORTED_BY_RUNTIME = 'alg_unsupported_by_runtime';
  public const R_MISSING_KID = 'missing_kid';
  public const R_UNKNOWN_KID = 'unknown_kid';
  public const R_BAD_SIGNATURE = 'bad_signature';
  public const R_EXPIRED = 'expired';
  public const R_NOT_YET_VALID = 'not_yet_valid';
  public const R_MISSING_CLAIM = 'missing_claim';
  public const R_BAD_ISSUER = 'bad_issuer';
  public const R_BAD_AUDIENCE = 'bad_audience';
  public const R_BAD_AZP = 'bad_azp';
  public const R_NONCE_MISMATCH = 'nonce_mismatch';

  public function __construct(
    public readonly string $reason,
    string $message,
    ?\Throwable $previous = NULL,
  ) {
    parent::__construct($message, 0, $previous);
  }

}
