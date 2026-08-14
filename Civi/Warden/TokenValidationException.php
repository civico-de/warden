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
  public const R_LOGOUT_SUBJECT_MISSING = 'logout_subject_missing';
  public const R_LOGOUT_EVENTS_INVALID = 'logout_events_invalid';
  public const R_LOGOUT_NONCE_PROHIBITED = 'logout_nonce_prohibited';
  public const R_LOGOUT_REPLAY = 'logout_replay';

  public function __construct(
    public readonly string $reason,
    string $message,
    ?\Throwable $previous = NULL,
  ) {
    parent::__construct($message, 0, $previous);
  }

  /**
   * Preserve stable audit reason codes while digitalcz owns the actual token
   * validation. No token or claim values are copied into the exception.
   */
  public static function fromOidc(\Throwable $error): self {
    $message = strtolower($error->getMessage());
    $reason = match (TRUE) {
      str_contains($message, 'nonce') => self::R_NONCE_MISMATCH,
      str_contains($message, 'authorized party'), str_contains($message, 'azp') => self::R_BAD_AZP,
      str_contains($message, 'audience'), str_contains($message, ' aud') => self::R_BAD_AUDIENCE,
      str_contains($message, 'issuer'), str_contains($message, ' iss') => self::R_BAD_ISSUER,
      str_contains($message, 'expired'), str_contains($message, 'expiration') => self::R_EXPIRED,
      str_contains($message, 'not before'), str_contains($message, 'issued at') => self::R_NOT_YET_VALID,
      str_contains($message, 'algorithm'), str_contains($message, ' alg') => self::R_ALG_NOT_ALLOWED,
      str_contains($message, 'signature'), str_contains($message, 'key'), str_contains($message, 'verify') => self::R_BAD_SIGNATURE,
      default => self::R_MALFORMED,
    };

    return new self($reason, 'OIDC token validation failed', $error);
  }

  /**
   * Map the purpose-specific mandatory and prohibited logout-token claims.
   */
  public static function fromOidcLogout(\Throwable $error): self {
    $message = strtolower($error->getMessage());
    $reason = match (TRUE) {
      str_contains($message, 'events') => self::R_LOGOUT_EVENTS_INVALID,
      str_contains($message, 'nonce') => self::R_LOGOUT_NONCE_PROHIBITED,
      str_contains($message, 'either a "sub" or "sid"'),
      str_contains($message, 'either a "sub" or a "sid"') => self::R_LOGOUT_SUBJECT_MISSING,
      default => self::fromOidc($error)->reason,
    };

    return new self($reason, 'OIDC logout-token validation failed', $error);
  }

}
