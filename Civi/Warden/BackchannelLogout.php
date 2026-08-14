<?php

declare(strict_types = 1);

namespace Civi\Warden;

use DigitalCz\OpenIDConnect\Exception\InvalidTokenException as OidcInvalidTokenException;
use DigitalCz\OpenIDConnect\Util\JWT;

// @mago-expect lint:cyclomatic-complexity
// Validation of the purpose-specific logout claims is intentionally kept next
// to replay checking and exact revocation so the security sequence is visible.
/**
 * Validate and apply one OIDC Back-Channel Logout request.
 */
final class BackchannelLogout {

  /**
   * @throws \Civi\Warden\TokenValidationException
   * @throws \CRM_Core_Exception
   */
  public static function apply(string $jwt): int {
    try {
      $issuer = JWT::claim($jwt, 'iss');
    }
    catch (\Throwable $e) {
      throw new TokenValidationException(TokenValidationException::R_MALFORMED, 'logout token is malformed', $e);
    }
    if (!is_string($issuer) || $issuer === '') {
      throw new TokenValidationException(TokenValidationException::R_MISSING_CLAIM, 'logout token carries no issuer');
    }

    $provider = ProviderRepository::findByIssuer($issuer);
    if ($provider === NULL) {
      throw new TokenValidationException(TokenValidationException::R_BAD_ISSUER, 'logout token issuer is not configured');
    }

    try {
      $token = OidcClient::forProvider($provider)->backChannelLogout()->handleLogoutRequest($jwt);
    }
    catch (OidcInvalidTokenException $e) {
      throw TokenValidationException::fromOidcLogout($e);
    }

    $all = $token->claims();
    $exp = $all['exp'] ?? NULL;
    if (!is_int($exp)) {
      throw new TokenValidationException(TokenValidationException::R_MISSING_CLAIM, 'logout token carries no usable exp claim');
    }
    $leeway = max(0, min(300, Value::int(\Civi::settings()->get('warden_clock_leeway'), 60)));
    if ((time() - $leeway) >= $exp) {
      throw new TokenValidationException(TokenValidationException::R_EXPIRED, 'logout token exp is in the past');
    }

    $subject = $all['sub'] ?? NULL;
    $sessionId = $all['sid'] ?? NULL;
    $tokenId = $all['jti'] ?? NULL;
    if (($subject !== NULL && (!is_string($subject) || $subject === ''))
      || ($sessionId !== NULL && (!is_string($sessionId) || $sessionId === ''))
      || !is_string($tokenId) || $tokenId === '') {
      throw new TokenValidationException(
        TokenValidationException::R_MALFORMED,
        'logout token sub, sid and jti claims must be non-empty strings',
      );
    }

    $claims = new LogoutTokenClaims($subject, $sessionId, $tokenId, $all);
    $replayKey = 'logout_jti_' . $provider->id . '_' . hash('sha256', $claims->tokenId);
    $count = SessionRegistry::revoke($provider, $claims);
    // Claim only after the durable revocation succeeded. If the database is
    // temporarily unavailable the IdP can retry the same signed token.
    if (!Cache::claim($replayKey, min(86_400, max(60, $exp - time() + $leeway)))) {
      throw new TokenValidationException(TokenValidationException::R_LOGOUT_REPLAY, 'logout token was already processed');
    }
    Audit::record(
      Options::EVENT_BACKCHANNEL_LOGOUT,
      $provider,
      NULL,
      NULL,
      sprintf('%d local session(s) revoked', $count),
      $claims->subject,
    );

    return $count;
  }

}
