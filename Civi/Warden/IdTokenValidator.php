<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;

// @mago-expect lint:cyclomatic-complexity
// @mago-expect lint:too-many-methods
// @mago-expect lint:kan-defect
// Every branch here is a distinct rule an ID token must satisfy. Splitting
// them across classes would scatter the security contract and make the
// adversarial suite harder to read against it, so the complexity is where it
// belongs: in one auditable place.
/**
 * ID-token validation. This class is the reason warden exists.
 *
 * It has no CiviCRM dependency and does no I/O: keys arrive through a
 * KeySource and the clock arrives as an argument, so every branch below is
 * reachable from a plain unit test with a crafted token.
 *
 * Order is load-bearing. The algorithm allow-list and the key lookup have to
 * run before verification because they decide HOW to verify; everything else
 * runs after, so no claim is ever read out of an unauthenticated token.
 */
final class IdTokenValidator {

  public function __construct(
    private readonly ValidationPolicy $policy,
    private readonly KeySource $keySource,
  ) {}

  /**
   * @param string $jwt
   *   The raw id_token.
   * @param string $expectedNonce
   *   The nonce minted for THIS authorization request and stored in state.
   * @param int|null $now
   *   Unix time; injectable so expiry tests do not sleep.
   *
   * @throws \Civi\Warden\TokenValidationException
   */
  public function validate(string $jwt, string $expectedNonce, ?int $now = NULL): IdTokenClaims {
    $now ??= time();

    $header = $this->readHeader($jwt);
    $alg = $this->checkAlgorithm($header);
    $key = $this->resolveKey($header, $alg);
    $claims = $this->verify($jwt, $key, $alg);

    $this->checkIssuer($claims);
    $this->checkAudience($claims);
    $this->checkTimes($claims, $now);
    $this->checkNonce($claims, $expectedNonce);

    return new IdTokenClaims($this->requireString($claims, 'sub'), $claims);
  }

  /**
   * @return array<string, mixed>
   */
  private function readHeader(string $jwt): array {
    $segments = explode('.', $jwt);
    if (count($segments) !== 3 || $segments[0] === '' || $segments[1] === '' || $segments[2] === '') {
      throw new TokenValidationException(
        TokenValidationException::R_MALFORMED,
        'ID token is not a three-part compact JWS',
      );
    }

    $raw = self::base64UrlDecode($segments[0]);
    $decoded = $raw === NULL ? NULL : json_decode($raw, TRUE);
    if (!is_array($decoded)) {
      throw new TokenValidationException(
        TokenValidationException::R_MALFORMED,
        'ID token header is not decodable JSON',
      );
    }

    /** @var array<string, mixed> $decoded */
    return $decoded;
  }

  /**
   * @param array<string, mixed> $header
   */
  private function checkAlgorithm(array $header): string {
    $alg = $header['alg'] ?? NULL;
    if (!is_string($alg) || $alg === '') {
      throw new TokenValidationException(
        TokenValidationException::R_MALFORMED,
        'ID token header carries no alg',
      );
    }

    // Called out separately from the allow-list so the audit trail can say
    // "someone tried an unsigned token", which is an attack and not a
    // misconfiguration. `none` never becomes acceptable by being allow-listed.
    if (strcasecmp($alg, 'none') === 0) {
      throw new TokenValidationException(
        TokenValidationException::R_ALG_NONE,
        'ID token claims to be unsigned',
      );
    }

    if (!in_array($alg, $this->policy->allowedAlgorithms, TRUE)) {
      throw new TokenValidationException(
        TokenValidationException::R_ALG_NOT_ALLOWED,
        sprintf('ID token alg %s is outside the configured allow-list', $alg),
      );
    }

    // Asked before decoding rather than inferred from a library exception
    // message. php-jwt 7.0.x has no PS256/PS384/PS512, so an RSA-PSS provider
    // lands here with a reason an operator can act on instead of a stack
    // trace. StatusCheck warns about the same gap at configuration time.
    if (!isset(JWT::$supported_algs[$alg])) {
      throw new TokenValidationException(
        TokenValidationException::R_ALG_UNSUPPORTED_BY_RUNTIME,
        sprintf(
          'ID token alg %s is allow-listed but this CiviCRM ships a firebase/php-jwt that cannot verify it',
          $alg,
        ),
      );
    }

    return $alg;
  }

  /**
   * @param array<string, mixed> $header
   */
  private function resolveKey(array $header, string $alg): Key {
    $kid = $header['kid'] ?? NULL;
    $keys = $this->keySource->keys();

    if (is_string($kid) && $kid !== '') {
      if (!isset($keys[$kid])) {
        // Exactly one retry. A rollover heals on the first login that needs
        // the new key; an attacker spraying invented kids gets one refetch,
        // then the cached set, because the refresh itself is TTL-guarded.
        $keys = $this->keySource->keys(TRUE);
      }
      if (!isset($keys[$kid])) {
        throw new TokenValidationException(
          TokenValidationException::R_UNKNOWN_KID,
          'ID token was signed with a key the provider does not publish',
        );
      }

      return $keys[$kid];
    }

    // No kid. Tolerated only when the provider publishes a single key, which
    // is the one case where there is nothing to guess.
    if (count($keys) === 1) {
      return (
        reset($keys)
        ?: throw new TokenValidationException(
          TokenValidationException::R_MISSING_KID,
          'ID token carries no kid and no key is available',
        )
      );
    }

    throw new TokenValidationException(
      TokenValidationException::R_MISSING_KID,
      sprintf('ID token carries no kid and the provider publishes %d keys', count($keys)),
    );
  }

  /**
   * Signature and library-level time checks.
   *
   * php-jwt matches the Key's own algorithm against the header, which is what
   * stops the RS256-public-key-as-HMAC-secret confusion; we do not re-implement
   * that, we depend on it and pin it with a test.
   *
   * @return array<string, mixed>
   */
  private function verify(string $jwt, Key $key, string $alg): array {
    $previousLeeway = JWT::$leeway;
    JWT::$leeway = $this->policy->leeway;
    try {
      $payload = JWT::decode($jwt, $key);
    }
    catch (SignatureInvalidException $e) {
      throw new TokenValidationException(
        TokenValidationException::R_BAD_SIGNATURE,
        'ID token signature does not verify',
        $e,
      );
    }
    catch (ExpiredException $e) {
      throw new TokenValidationException(TokenValidationException::R_EXPIRED, 'ID token has expired', $e);
    }
    catch (BeforeValidException $e) {
      throw new TokenValidationException(TokenValidationException::R_NOT_YET_VALID, 'ID token is not valid yet', $e);
    }
    // Two catches rather than one union type: the formatter strips the spaces
    // around `|` and the code standard requires them, and this is not a fight
    // worth having in the middle of signature verification.
    catch (\UnexpectedValueException $e) {
      // Wrong key type for the algorithm, undecodable body, unsupported alg
      // reached through a library path we did not pre-empt.
      throw self::undecodable($alg, $e);
    }
    catch (\DomainException $e) {
      throw self::undecodable($alg, $e);
    }
    finally {
      JWT::$leeway = $previousLeeway;
    }

    $claims = json_decode((string) json_encode($payload), TRUE);
    if (!is_array($claims)) {
      throw new TokenValidationException(TokenValidationException::R_MALFORMED, 'ID token payload is not an object');
    }

    /** @var array<string, mixed> $claims */
    return $claims;
  }

  /**
   * @param array<string, mixed> $claims
   */
  private function checkIssuer(array $claims): void {
    $iss = $this->requireString($claims, 'iss');
    if (!hash_equals($this->policy->issuer, $iss)) {
      throw new TokenValidationException(
        TokenValidationException::R_BAD_ISSUER,
        'ID token was issued by a different issuer than the one configured',
      );
    }
  }

  /**
   * @param array<string, mixed> $claims
   */
  private function checkAudience(array $claims): void {
    /** @var mixed $aud */
    $aud = $claims['aud'] ?? NULL;
    $audiences = is_string($aud) ? [$aud] : $aud;
    if (!is_array($audiences) || $audiences === []) {
      throw new TokenValidationException(
        TokenValidationException::R_MISSING_CLAIM,
        'ID token carries no usable aud claim',
      );
    }

    $matched = FALSE;
    /** @var mixed $candidate */
    foreach ($audiences as $candidate) {
      if (!is_string($candidate)) {
        continue;
      }
      // No early break: comparing every entry keeps the work independent of
      // where in the list our client id sits.
      $matched = $matched || hash_equals($this->policy->clientId, $candidate);
    }
    if (!$matched) {
      throw new TokenValidationException(
        TokenValidationException::R_BAD_AUDIENCE,
        'ID token aud does not contain this client',
      );
    }

    /** @var mixed $azp */
    $azp = $claims['azp'] ?? NULL;
    if ($azp !== NULL) {
      if (!is_string($azp) || !hash_equals($this->policy->clientId, $azp)) {
        throw new TokenValidationException(
          TokenValidationException::R_BAD_AZP,
          'ID token azp names a different client — the token was minted for someone else',
        );
      }

      return;
    }

    // Multiple audiences and no azp: OIDC Core 3.1.3.7 requires the authorized
    // party to be named, and without it we cannot tell whether this token was
    // meant for us or merely mentions us.
    if (count($audiences) > 1) {
      throw new TokenValidationException(
        TokenValidationException::R_MISSING_CLAIM,
        'ID token has multiple audiences but no azp',
      );
    }
  }

  /**
   * Explicit time checks on top of php-jwt's.
   *
   * Not redundant: php-jwt treats `exp` and `iat` as optional, OIDC requires
   * both, and pinning the comparisons here makes the leeway semantics
   * something a test can hold still across library upgrades.
   *
   * @param array<string, mixed> $claims
   */
  private function checkTimes(array $claims, int $now): void {
    $leeway = $this->policy->leeway;

    $exp = $this->requireInt($claims, 'exp');
    if (($now - $leeway) >= $exp) {
      throw new TokenValidationException(TokenValidationException::R_EXPIRED, 'ID token exp is in the past');
    }

    $iat = $this->requireInt($claims, 'iat');
    if ($iat > ($now + $leeway)) {
      throw new TokenValidationException(TokenValidationException::R_NOT_YET_VALID, 'ID token iat is in the future');
    }

    if (array_key_exists('nbf', $claims)) {
      $nbf = $this->requireInt($claims, 'nbf');
      if ($nbf > ($now + $leeway)) {
        throw new TokenValidationException(TokenValidationException::R_NOT_YET_VALID, 'ID token nbf is in the future');
      }
    }
  }

  /**
   * @param array<string, mixed> $claims
   */
  private function checkNonce(array $claims, string $expectedNonce): void {
    if ($expectedNonce === '') {
      // Never reached through the login flow — LoginFlow always mints one — but
      // an empty expectation must not become a wildcard if it ever is.
      throw new TokenValidationException(
        TokenValidationException::R_NONCE_MISMATCH,
        'no nonce was recorded for this authorization request',
      );
    }

    $nonce = $claims['nonce'] ?? NULL;
    if (!is_string($nonce) || !hash_equals($expectedNonce, $nonce)) {
      throw new TokenValidationException(
        TokenValidationException::R_NONCE_MISMATCH,
        'ID token nonce does not match the one minted for this login',
      );
    }
  }

  /**
   * @param array<string, mixed> $claims
   */
  private function requireString(array $claims, string $name): string {
    $value = $claims[$name] ?? NULL;
    if (!is_string($value) || $value === '') {
      throw new TokenValidationException(
        TokenValidationException::R_MISSING_CLAIM,
        sprintf('ID token carries no usable %s claim', $name),
      );
    }

    return $value;
  }

  /**
   * @param array<string, mixed> $claims
   */
  private function requireInt(array $claims, string $name): int {
    /** @var mixed $value */
    $value = $claims[$name] ?? NULL;
    if (is_int($value)) {
      return $value;
    }
    // Some providers send these as JSON numbers with a fractional part.
    if (is_float($value) && is_finite($value)) {
      return (int) floor($value);
    }

    throw new TokenValidationException(
      TokenValidationException::R_MISSING_CLAIM,
      sprintf('ID token carries no usable %s claim', $name),
    );
  }

  private static function undecodable(string $alg, \Throwable $e): TokenValidationException {
    return new TokenValidationException(
      TokenValidationException::R_MALFORMED,
      sprintf('ID token (%s) could not be decoded', $alg),
      $e,
    );
  }

  private static function base64UrlDecode(string $input): ?string {
    $remainder = strlen($input) % 4;
    if ($remainder !== 0) {
      $input .= str_repeat('=', 4 - $remainder);
    }
    $decoded = base64_decode(strtr($input, '-_', '+/'), TRUE);

    return $decoded === FALSE ? NULL : $decoded;
  }

}
