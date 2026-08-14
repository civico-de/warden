<?php

declare(strict_types = 1);

namespace Civi\Warden\Tests\Support;

use Civi\Warden\IdTokenValidator;
use Civi\Warden\TokenValidationException;
use Civi\Warden\ValidationPolicy;
use Firebase\JWT\Key;
use PHPUnit\Framework\TestCase;

/**
 * The adversarial ID-token suite, written once and run twice: as a pure unit
 * test (tests/unit) and inside the headless suite (tests/phpunit) so CI gates
 * it. Duplicating the table would be the surest way to let one copy rot.
 *
 * Every case here is an attack or a broken provider, and each asserts the
 * REASON as well as the refusal — a validator that rejects everything for the
 * wrong reason passes a weaker test and fails a real deployment.
 */
abstract class IdTokenValidatorContract extends TestCase {

  private const NONCE = 'nonce-abcdef0123456789';

  /**
   * Anchored to the real clock, not a fixed constant: php-jwt does its own
   * exp/nbf/iat checks against `time()` and cannot be told otherwise, so a
   * fixture dated years from now is "not yet valid" to the library however
   * carefully the test injects its own clock.
   */
  private int $now;

  protected function setUp(): void {
    parent::setUp();
    $this->now = time();
  }

  private function validator(
    ?ArrayKeySource $keys = NULL,
    ?string $issuer = NULL,
    ?string $clientId = NULL,
    ?array $algorithms = NULL,
    int $leeway = 60,
  ): IdTokenValidator {
    return new IdTokenValidator(
      ValidationPolicy::create(
        $issuer ?? JwtFixture::ISSUER,
        $clientId ?? JwtFixture::CLIENT_ID,
        $algorithms ?? ['RS256'],
        $leeway,
      ),
      $keys ?? new ArrayKeySource(JwtFixture::keySet()),
    );
  }

  /**
   * @param array<string, mixed> $overrides
   *
   * @return array<string, mixed>
   */
  private function claims(array $overrides = []): array {
    return array_merge(JwtFixture::claims($this->now, self::NONCE), $overrides);
  }

  private function expectReason(string $reason, callable $act): void {
    try {
      $act();
    }
    catch (TokenValidationException $e) {
      self::assertSame($reason, $e->reason, 'wrong rejection reason: ' . $e->getMessage());

      return;
    }

    self::fail("expected the token to be rejected with reason '{$reason}', but it was accepted");
  }

  // --- The one that must pass -------------------------------------------

  public function testAValidTokenIsAccepted(): void {
    $claims = $this->validator()->validate(
      JwtFixture::sign($this->claims()),
      self::NONCE,
      $this->now,
    );

    self::assertSame('subject-0001', $claims->subject);
    self::assertSame(['someone@example.org', TRUE], $claims->email());
    self::assertSame(['crm-staff', 'unrelated'], $claims->claim('realm_access.roles'));
  }

  // --- Signature and algorithm ------------------------------------------

  public function testAlgNoneIsRejected(): void {
    $this->expectReason(
      TokenValidationException::R_ALG_NONE,
      fn () => $this->validator()->validate(JwtFixture::unsigned($this->claims()), self::NONCE, $this->now),
    );
  }

  public function testAlgNoneIsRejectedEvenWhenSomehowAllowListed(): void {
    // `none` must never become acceptable by configuration.
    $this->expectReason(
      TokenValidationException::R_ALG_NONE,
      fn () => $this->validator(algorithms: ['RS256', 'none'])
        ->validate(JwtFixture::unsigned($this->claims()), self::NONCE, $this->now),
    );
  }

  public function testAlgorithmOutsideTheAllowListIsRejected(): void {
    $this->expectReason(
      TokenValidationException::R_ALG_NOT_ALLOWED,
      fn () => $this->validator()->validate(JwtFixture::hmac($this->claims()), self::NONCE, $this->now),
    );
  }

  public function testAlgorithmConfusionIsRejectedEvenWhenHs256IsAllowed(): void {
    // The classic attack: sign with HMAC using the RSA PUBLIC key as the
    // shared secret, hoping the verifier picks the algorithm from the token.
    // php-jwt binds each Key to an algorithm; this pins that it does.
    $public = JwtFixture::keyPair('a')['public'];
    $forged = \Firebase\JWT\JWT::encode($this->claims(), $public, 'HS256', JwtFixture::KID);

    $this->expectReason(
      TokenValidationException::R_MALFORMED,
      fn () => $this->validator(algorithms: ['RS256', 'HS256'])->validate($forged, self::NONCE, $this->now),
    );
  }

  public function testAWrongSignatureIsRejected(): void {
    // Signed with key 'b' but presented under key 'a''s kid.
    $this->expectReason(
      TokenValidationException::R_BAD_SIGNATURE,
      fn () => $this->validator()->validate(
        JwtFixture::sign($this->claims(), 'RS256', JwtFixture::KID, 'b'),
        self::NONCE,
        $this->now,
      ),
    );
  }

  public function testAnUnknownKidIsRejectedAfterExactlyOneRefetch(): void {
    $keys = new ArrayKeySource(JwtFixture::keySet());

    $this->expectReason(
      TokenValidationException::R_UNKNOWN_KID,
      fn () => $this->validator($keys)->validate(
        JwtFixture::sign($this->claims(), 'RS256', 'key-that-does-not-exist'),
        self::NONCE,
        $this->now,
      ),
    );

    self::assertSame(1, $keys->refreshCount, 'the validator must refetch exactly once on an unknown kid');
  }

  public function testAKeyRolloverHealsOnTheRefetch(): void {
    $rolled = ['key-3' => new Key(JwtFixture::keyPair('a')['public'], 'RS256')];
    $keys = new ArrayKeySource([], $rolled);

    $claims = $this->validator($keys)->validate(
      JwtFixture::sign($this->claims(), 'RS256', 'key-3'),
      self::NONCE,
      $this->now,
    );

    self::assertSame('subject-0001', $claims->subject);
    self::assertSame(1, $keys->refreshCount);
  }

  public function testAMissingKidWithSeveralKeysIsRejected(): void {
    $this->expectReason(
      TokenValidationException::R_MISSING_KID,
      fn () => $this->validator()->validate(
        JwtFixture::sign($this->claims(), 'RS256', NULL),
        self::NONCE,
        $this->now,
      ),
    );
  }

  public function testAMissingKidWithExactlyOneKeyIsAccepted(): void {
    $keys = new ArrayKeySource([JwtFixture::KID => new Key(JwtFixture::keyPair('a')['public'], 'RS256')]);

    $claims = $this->validator($keys)->validate(
      JwtFixture::sign($this->claims(), 'RS256', NULL),
      self::NONCE,
      $this->now,
    );

    self::assertSame('subject-0001', $claims->subject);
  }

  public function testGarbageIsRejectedAsMalformed(): void {
    foreach (['', 'not-a-jwt', 'a.b', 'a.b.c.d', '..', 'ﻝ.ﻝ.ﻝ'] as $junk) {
      $this->expectReason(
        TokenValidationException::R_MALFORMED,
        fn () => $this->validator()->validate($junk, self::NONCE, $this->now),
      );
    }
  }

  // --- Issuer, audience, azp --------------------------------------------

  public function testAWrongIssuerIsRejected(): void {
    $this->expectReason(
      TokenValidationException::R_BAD_ISSUER,
      fn () => $this->validator()->validate(
        JwtFixture::sign($this->claims(['iss' => 'https://evil.example.org'])),
        self::NONCE,
        $this->now,
      ),
    );
  }

  public function testAnIssuerPrefixIsNotEnough(): void {
    // A provider whose issuer merely starts with ours must not be accepted.
    $this->expectReason(
      TokenValidationException::R_BAD_ISSUER,
      fn () => $this->validator()->validate(
        JwtFixture::sign($this->claims(['iss' => JwtFixture::ISSUER . '.evil.org'])),
        self::NONCE,
        $this->now,
      ),
    );
  }

  public function testAWrongAudienceIsRejected(): void {
    $this->expectReason(
      TokenValidationException::R_BAD_AUDIENCE,
      fn () => $this->validator()->validate(
        JwtFixture::sign($this->claims(['aud' => 'some-other-client'])),
        self::NONCE,
        $this->now,
      ),
    );
  }

  public function testAnAudienceArrayContainingUsIsAcceptedWhenAzpNamesUs(): void {
    $claims = $this->validator()->validate(
      JwtFixture::sign($this->claims([
        'aud' => ['some-other-client', JwtFixture::CLIENT_ID],
        'azp' => JwtFixture::CLIENT_ID,
      ])),
      self::NONCE,
      $this->now,
    );

    self::assertSame('subject-0001', $claims->subject);
  }

  public function testMultipleAudiencesWithoutAzpAreRejected(): void {
    $this->expectReason(
      TokenValidationException::R_MISSING_CLAIM,
      fn () => $this->validator()->validate(
        JwtFixture::sign($this->claims(['aud' => ['some-other-client', JwtFixture::CLIENT_ID]])),
        self::NONCE,
        $this->now,
      ),
    );
  }

  public function testAnAzpNamingAnotherClientIsRejected(): void {
    // The token was minted for a different client at the same provider.
    $this->expectReason(
      TokenValidationException::R_BAD_AZP,
      fn () => $this->validator()->validate(
        JwtFixture::sign($this->claims(['azp' => 'some-other-client'])),
        self::NONCE,
        $this->now,
      ),
    );
  }

  public function testAMissingAudienceIsRejected(): void {
    $claims = $this->claims();
    unset($claims['aud']);

    $this->expectReason(
      TokenValidationException::R_MISSING_CLAIM,
      fn () => $this->validator()->validate(JwtFixture::sign($claims), self::NONCE, $this->now),
    );
  }

  // --- Time -------------------------------------------------------------

  public function testAnExpiredTokenIsRejected(): void {
    $this->expectReason(
      TokenValidationException::R_EXPIRED,
      fn () => $this->validator()->validate(
        JwtFixture::sign($this->claims(['exp' => $this->now - 3600, 'iat' => $this->now - 7200])),
        self::NONCE,
        $this->now,
      ),
    );
  }

  public function testATokenThatExpiredWithinTheLeewayIsStillAccepted(): void {
    $claims = $this->validator()->validate(
      JwtFixture::sign($this->claims(['exp' => $this->now - 30])),
      self::NONCE,
      $this->now,
    );

    self::assertSame('subject-0001', $claims->subject);
  }

  public function testATokenThatExpiredJustOutsideTheLeewayIsRejected(): void {
    $this->expectReason(
      TokenValidationException::R_EXPIRED,
      fn () => $this->validator()->validate(
        JwtFixture::sign($this->claims(['exp' => $this->now - 61])),
        self::NONCE,
        $this->now,
      ),
    );
  }

  public function testATokenIssuedInTheFutureIsRejected(): void {
    $this->expectReason(
      TokenValidationException::R_NOT_YET_VALID,
      fn () => $this->validator()->validate(
        JwtFixture::sign($this->claims(['iat' => $this->now + 3600, 'exp' => $this->now + 7200])),
        self::NONCE,
        $this->now,
      ),
    );
  }

  public function testANotYetValidTokenIsRejected(): void {
    $this->expectReason(
      TokenValidationException::R_NOT_YET_VALID,
      fn () => $this->validator()->validate(
        JwtFixture::sign($this->claims(['nbf' => $this->now + 3600])),
        self::NONCE,
        $this->now,
      ),
    );
  }

  public function testAMissingExpIsRejected(): void {
    // php-jwt treats exp as optional; OIDC does not.
    $claims = $this->claims();
    unset($claims['exp']);

    $this->expectReason(
      TokenValidationException::R_MISSING_CLAIM,
      fn () => $this->validator()->validate(JwtFixture::sign($claims), self::NONCE, $this->now),
    );
  }

  public function testAMissingIatIsRejected(): void {
    $claims = $this->claims();
    unset($claims['iat']);

    $this->expectReason(
      TokenValidationException::R_MISSING_CLAIM,
      fn () => $this->validator()->validate(JwtFixture::sign($claims), self::NONCE, $this->now),
    );
  }

  // --- Nonce ------------------------------------------------------------

  public function testAMissingNonceIsRejected(): void {
    $claims = $this->claims();
    unset($claims['nonce']);

    $this->expectReason(
      TokenValidationException::R_NONCE_MISMATCH,
      fn () => $this->validator()->validate(JwtFixture::sign($claims), self::NONCE, $this->now),
    );
  }

  public function testAMismatchedNonceIsRejected(): void {
    $this->expectReason(
      TokenValidationException::R_NONCE_MISMATCH,
      fn () => $this->validator()->validate(
        JwtFixture::sign($this->claims(['nonce' => 'some-other-nonce'])),
        self::NONCE,
        $this->now,
      ),
    );
  }

  public function testAReplayedTokenFailsAgainstAFreshNonce(): void {
    // A captured token replayed into a NEW login attempt: the state store has
    // minted a different nonce, so the same bytes no longer validate. This is
    // the second half of replay protection; the first half is the state store
    // refusing to hand out the same state twice.
    $token = JwtFixture::sign($this->claims());

    self::assertSame('subject-0001', $this->validator()->validate($token, self::NONCE, $this->now)->subject);

    $this->expectReason(
      TokenValidationException::R_NONCE_MISMATCH,
      fn () => $this->validator()->validate($token, 'a-different-nonce-for-the-next-login', $this->now),
    );
  }

  public function testAnEmptyExpectedNonceIsNeverAWildcard(): void {
    $this->expectReason(
      TokenValidationException::R_NONCE_MISMATCH,
      fn () => $this->validator()->validate(JwtFixture::sign($this->claims(['nonce' => ''])), '', $this->now),
    );
  }

  // --- Subject ----------------------------------------------------------

  public function testAMissingSubjectIsRejected(): void {
    $claims = $this->claims();
    unset($claims['sub']);

    $this->expectReason(
      TokenValidationException::R_MISSING_CLAIM,
      fn () => $this->validator()->validate(JwtFixture::sign($claims), self::NONCE, $this->now),
    );
  }

  public function testAnEmptySubjectIsRejected(): void {
    $this->expectReason(
      TokenValidationException::R_MISSING_CLAIM,
      fn () => $this->validator()->validate(JwtFixture::sign($this->claims(['sub' => ''])), self::NONCE, $this->now),
    );
  }

  // --- Policy hygiene ---------------------------------------------------

  public function testAnEmptyAllowListRejectsEverything(): void {
    // A misconfiguration must fail closed, never open.
    $this->expectReason(
      TokenValidationException::R_ALG_NOT_ALLOWED,
      fn () => $this->validator(algorithms: [])->validate(JwtFixture::sign($this->claims()), self::NONCE, $this->now),
    );
  }

  public function testAnAlgorithmThisRuntimeCannotVerifyIsNamedAsSuch(): void {
    // PS256 is allow-listed but firebase/php-jwt 7.0.x — what CiviCRM 6.x
    // ships — has no RSA-PSS. The operator gets a reason they can act on.
    if (isset(\Firebase\JWT\JWT::$supported_algs['PS256'])) {
      self::markTestSkipped('this php-jwt supports PS256, so the mismatch cannot be reproduced');
    }

    $token = JwtFixture::sign($this->claims());
    // Re-header the token to claim PS256 without re-signing: the alg check
    // runs before any key is touched, so the body never matters.
    [, $payload, $signature] = explode('.', $token);
    $header = rtrim(strtr(base64_encode((string) json_encode(['alg' => 'PS256', 'typ' => 'JWT', 'kid' => JwtFixture::KID])), '+/', '-_'), '=');

    $this->expectReason(
      TokenValidationException::R_ALG_UNSUPPORTED_BY_RUNTIME,
      fn () => $this->validator(algorithms: ['RS256', 'PS256'])
        ->validate($header . '.' . $payload . '.' . $signature, self::NONCE, $this->now),
    );
  }

}
