<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Test;
use Civi\Test\HeadlessInterface;
use Civi\Test\TransactionalInterface;
use Civi\Warden\Tests\Support\JwtFixture;
use DigitalCz\OpenIDConnect\BackChannelLogout\LogoutToken;
use DigitalCz\OpenIDConnect\BackChannelLogout\LogoutTokenValidator;
use DigitalCz\OpenIDConnect\Client\IdToken;
use DigitalCz\OpenIDConnect\Client\IdTokenValidator;
use DigitalCz\OpenIDConnect\Discovery\JwksLoader;
use DigitalCz\OpenIDConnect\Exception\InvalidTokenException;
use PHPUnit\Framework\TestCase;
use Symfony\Contracts\Cache\ItemInterface;

/**
 * Contract tests for the small adapters around digitalcz/openid-connect.
 *
 * @group headless
 * @covers \Civi\Warden\OidcCache
 * @covers \Civi\Warden\OidcCacheItem
 * @covers \Civi\Warden\RefreshableJwksLoader
 * @covers \Civi\Warden\RefreshingIdTokenValidator
 * @covers \Civi\Warden\RefreshingLogoutTokenValidator
 * @covers \Civi\Warden\TokenValidationException
 * @covers \Civi\Warden\IdTokenClaims
 * @covers \Civi\Warden\LogoutTokenClaims
 * @covers \Civi\Warden\Value
 * @covers \Civi\Warden\Http
 * @covers \Civi\Warden\Cache
 */
final class OidcSupportHeadlessTest extends TestCase implements HeadlessInterface, TransactionalInterface {

  public function setUpHeadless(): Test\CiviEnvBuilder {
    return Test::headless()
      ->install(['org.civicrm.search_kit', 'org.civicrm.afform', 'authx', 'standaloneusers'])
      ->installMe(__DIR__)
      ->apply();
  }

  public function testOidcCacheMemoizesAndDeletesValues(): void {
    $cache = new OidcCache();
    $key = 'support-' . bin2hex(random_bytes(8));
    $calls = 0;
    $metadata = NULL;
    $callback = static function (ItemInterface $item, bool &$save) use (&$calls): array {
      ++$calls;
      $save = TRUE;
      self::assertFalse($item->isHit());
      self::assertNull($item->get());
      self::assertSame($item, $item->set('value'));
      self::assertSame('value', $item->get());

      return ['call' => $calls];
    };

    self::assertSame(['call' => 1], $cache->get($key, $callback, metadata: $metadata));
    self::assertSame(['call' => 1], $cache->get($key, $callback));
    self::assertSame(1, $calls);
    self::assertIsInt($metadata[ItemInterface::METADATA_EXPIRY] ?? NULL);

    self::assertTrue($cache->delete($key));
    self::assertSame(['call' => 2], $cache->get($key, $callback));
  }

  public function testWardenCacheKeepsFailuresShortAndSuccessTimestampsSeparate(): void {
    $key = 'support-failure-' . bin2hex(random_bytes(8));
    $calls = 0;
    try {
      Cache::remember($key, 900, static function () use (&$calls): never {
        ++$calls;
        throw new \RuntimeException('temporary provider failure');
      });
    }
    catch (\RuntimeException $e) {
      self::assertSame('temporary provider failure', $e->getMessage());
    }

    try {
      Cache::remember($key, 900, static function () use (&$calls): string {
        ++$calls;

        return 'must-not-run';
      });
      self::fail('the short failure entry must prevent an immediate retry');
    }
    catch (\CRM_Core_Exception $e) {
      self::assertStringContainsString('still failing', $e->getMessage());
    }
    self::assertSame(1, $calls);

    Cache::forget($key);
    self::assertSame('recovered', Cache::remember($key, 900, static fn (): string => 'recovered'));
    self::assertIsInt(Cache::fetchedAt($key));
  }

  public function testReplayClaimsAreAtomicAndCacheTtlIsClamped(): void {
    $key = 'support-claim-' . bin2hex(random_bytes(8));
    self::assertTrue(Cache::claim($key, 1));
    self::assertFalse(Cache::claim($key, 1));

    \Civi::settings()->set('warden_discovery_ttl', 1);
    self::assertSame(300, Cache::ttl());
    \Civi::settings()->set('warden_discovery_ttl', 99_999);
    self::assertSame(3600, Cache::ttl());
    \Civi::settings()->set('warden_discovery_ttl', 'invalid');
    self::assertSame(900, Cache::ttl());
  }

  public function testCacheItemImplementsTheCompleteNoOpExpiryContract(): void {
    $item = new OidcCacheItem('item-key');

    self::assertSame('item-key', $item->getKey());
    self::assertSame($item, $item->expiresAfter(60));
    self::assertSame($item, $item->expiresAt(new \DateTimeImmutable('+1 minute')));
    self::assertSame($item, $item->tag(['oidc', 'warden']));
    self::assertSame([], $item->getMetadata());
  }

  public function testUnknownKidRefreshesTheCachedKeySetOnlyOnce(): void {
    $inner = new class() implements JwksLoader {

      public int $calls = 0;

      /**
       * @return array<string, mixed>
       */
      public function load(string $jwksUri): array {
        ++$this->calls;

        return ['keys' => [['kid' => $this->calls === 1 ? 'old-key' : 'new-key']]];
      }

    };
    $uri = 'https://keys-' . bin2hex(random_bytes(6)) . '.example.org/jwks';
    $loader = new RefreshableJwksLoader($inner, new OidcCache(), 900, 'support-secret');
    $token = JwtFixture::sign(JwtFixture::claims(time(), 'nonce'), kid: 'new-key');

    $initialKeys = $loader->load($uri);
    self::assertSame([['kid' => 'old-key']], $initialKeys['keys'] ?? NULL);
    self::assertTrue($loader->refreshForUnknownKid($uri, $token));
    self::assertSame(2, $inner->calls);
    self::assertFalse($loader->refreshForUnknownKid($uri, $token), 'the refreshed key is now known');
    self::assertFalse($loader->refreshForUnknownKid($uri, JwtFixture::sign(
      JwtFixture::claims(time(), 'nonce'),
      kid: NULL,
    )));
    self::assertFalse(
      $loader->refreshForUnknownKid($uri, JwtFixture::sign(
        JwtFixture::claims(time(), 'nonce'),
        kid: 'another-new-key',
      )),
      'the per-URI refresh budget permits no second refresh',
    );
  }

  public function testUnknownKidRefreshRequiresAKeyList(): void {
    $inner = new class() implements JwksLoader {

      public function load(string $jwksUri): array {
        return ['keys' => 'not-a-list'];
      }

    };
    $loader = new RefreshableJwksLoader($inner, new OidcCache(), 900, 'invalid-key-list');

    self::assertFalse($loader->refreshForUnknownKid(
      'https://invalid-keys.example.org/jwks',
      JwtFixture::sign(JwtFixture::claims(time(), 'nonce'), kid: 'unknown-key'),
    ));
  }

  public function testIdTokenValidatorRetriesAfterUnknownKidRefresh(): void {
    $innerKeys = new class() implements JwksLoader {

      public int $calls = 0;

      /**
       * @return array<string, mixed>
       */
      public function load(string $jwksUri): array {
        ++$this->calls;

        return ['keys' => [['kid' => $this->calls === 1 ? 'old-key' : 'new-key']]];
      }

    };
    $validator = new class() implements IdTokenValidator {

      public int $calls = 0;

      public function validate(#[\SensitiveParameter] IdToken $token, ?string $nonce = NULL): void {
        if (++$this->calls === 1) {
          throw new InvalidTokenException('unknown verification key');
        }
      }

    };
    $uri = 'https://id-retry-' . bin2hex(random_bytes(6)) . '.example.org/jwks';
    $keys = new RefreshableJwksLoader($innerKeys, new OidcCache(), 900, 'id-retry-secret');
    $token = new IdToken(JwtFixture::sign(JwtFixture::claims(time(), 'nonce'), kid: 'new-key'));

    (new RefreshingIdTokenValidator($validator, $keys, $uri))->validate($token, 'nonce');

    self::assertSame(2, $validator->calls);
    self::assertSame(2, $innerKeys->calls);
  }

  public function testLogoutTokenValidatorRetriesAfterUnknownKidRefresh(): void {
    $innerKeys = new class() implements JwksLoader {

      public int $calls = 0;

      /**
       * @return array<string, mixed>
       */
      public function load(string $jwksUri): array {
        ++$this->calls;

        return ['keys' => [['kid' => $this->calls === 1 ? 'old-key' : 'new-key']]];
      }

    };
    $validator = new class() implements LogoutTokenValidator {

      public int $calls = 0;

      public function validate(#[\SensitiveParameter] LogoutToken $token): void {
        if (++$this->calls === 1) {
          throw new InvalidTokenException('unknown verification key');
        }
      }

    };
    $uri = 'https://logout-retry-' . bin2hex(random_bytes(6)) . '.example.org/jwks';
    $keys = new RefreshableJwksLoader($innerKeys, new OidcCache(), 900, 'logout-retry-secret');
    $token = new LogoutToken(JwtFixture::sign([
      'iss' => JwtFixture::ISSUER,
      'aud' => JwtFixture::CLIENT_ID,
      'iat' => time(),
      'jti' => 'logout-jti',
      'sid' => 'session-id',
      'events' => [],
    ], kid: 'new-key'));

    (new RefreshingLogoutTokenValidator($validator, $keys, $uri))->validate($token);

    self::assertSame(2, $validator->calls);
    self::assertSame(2, $innerKeys->calls);
  }

  public function testIdTokenValidatorPreservesOriginalErrorWhenRefreshIsImpossible(): void {
    $original = new InvalidTokenException('original id-token failure');
    $validator = new class($original) implements IdTokenValidator {

      public function __construct(
        private readonly InvalidTokenException $failure,
      ) {}

      public function validate(#[\SensitiveParameter] IdToken $token, ?string $nonce = NULL): void {
        throw $this->failure;
      }

    };
    $innerKeys = new class() implements JwksLoader {

      public function load(string $jwksUri): array {
        return ['keys' => []];
      }

    };
    $keys = new RefreshableJwksLoader($innerKeys, new OidcCache(), 900, 'id-no-refresh');
    $token = new IdToken(JwtFixture::sign(JwtFixture::claims(time(), 'nonce'), kid: NULL));

    try {
      (new RefreshingIdTokenValidator($validator, $keys, 'https://keys.example.org'))->validate($token);
      self::fail('the original validation error must survive');
    }
    catch (InvalidTokenException $e) {
      self::assertSame($original, $e);
    }
  }

  public function testIdTokenValidatorPreservesOriginalErrorWhenRefreshFails(): void {
    $original = new InvalidTokenException('original id-token failure');
    $validator = new class($original) implements IdTokenValidator {

      public function __construct(
        private readonly InvalidTokenException $failure,
      ) {}

      public function validate(#[\SensitiveParameter] IdToken $token, ?string $nonce = NULL): void {
        throw $this->failure;
      }

    };
    $innerKeys = new class() implements JwksLoader {

      public function load(string $jwksUri): array {
        throw new \RuntimeException('temporary JWKS failure');
      }

    };
    $keys = new RefreshableJwksLoader($innerKeys, new OidcCache(), 900, 'id-refresh-failure');
    $token = new IdToken(JwtFixture::sign(JwtFixture::claims(time(), 'nonce'), kid: 'new-key'));

    try {
      (new RefreshingIdTokenValidator($validator, $keys, 'https://keys.example.org'))->validate($token);
      self::fail('the original validation error must survive');
    }
    catch (InvalidTokenException $e) {
      self::assertSame($original, $e);
    }
  }

  public function testLogoutValidatorPreservesOriginalErrorWhenRefreshIsImpossible(): void {
    $original = new InvalidTokenException('original logout-token failure');
    $validator = new class($original) implements LogoutTokenValidator {

      public function __construct(
        private readonly InvalidTokenException $failure,
      ) {}

      public function validate(#[\SensitiveParameter] LogoutToken $token): void {
        throw $this->failure;
      }

    };
    $innerKeys = new class() implements JwksLoader {

      public function load(string $jwksUri): array {
        return ['keys' => []];
      }

    };
    $keys = new RefreshableJwksLoader($innerKeys, new OidcCache(), 900, 'logout-no-refresh');
    $token = new LogoutToken(JwtFixture::sign(['events' => []], kid: NULL));

    try {
      (new RefreshingLogoutTokenValidator($validator, $keys, 'https://keys.example.org'))->validate($token);
      self::fail('the original validation error must survive');
    }
    catch (InvalidTokenException $e) {
      self::assertSame($original, $e);
    }
  }

  public function testLogoutValidatorPreservesOriginalErrorWhenRefreshFails(): void {
    $original = new InvalidTokenException('original logout-token failure');
    $validator = new class($original) implements LogoutTokenValidator {

      public function __construct(
        private readonly InvalidTokenException $failure,
      ) {}

      public function validate(#[\SensitiveParameter] LogoutToken $token): void {
        throw $this->failure;
      }

    };
    $innerKeys = new class() implements JwksLoader {

      public function load(string $jwksUri): array {
        throw new \RuntimeException('temporary JWKS failure');
      }

    };
    $keys = new RefreshableJwksLoader($innerKeys, new OidcCache(), 900, 'logout-refresh-failure');
    $token = new LogoutToken(JwtFixture::sign(['events' => []], kid: 'new-key'));

    try {
      (new RefreshingLogoutTokenValidator($validator, $keys, 'https://keys.example.org'))->validate($token);
      self::fail('the original validation error must survive');
    }
    catch (InvalidTokenException $e) {
      self::assertSame($original, $e);
    }
  }

  /**
   * @dataProvider tokenErrorProvider
   */
  public function testOidcErrorsMapToStableAuditReasons(string $message, string $reason): void {
    $original = new InvalidTokenException($message);
    $mapped = TokenValidationException::fromOidc($original);

    self::assertSame($reason, $mapped->reason);
    self::assertSame('OIDC token validation failed', $mapped->getMessage());
    self::assertSame($original, $mapped->getPrevious());
  }

  /**
   * @return array<string, array{string, string}>
   */
  public function tokenErrorProvider(): array {
    return [
      'nonce' => ['nonce mismatch', TokenValidationException::R_NONCE_MISMATCH],
      'authorized party' => ['authorized party mismatch', TokenValidationException::R_BAD_AZP],
      'audience' => ['audience mismatch', TokenValidationException::R_BAD_AUDIENCE],
      'issuer' => ['issuer mismatch', TokenValidationException::R_BAD_ISSUER],
      'expired' => ['token expired', TokenValidationException::R_EXPIRED],
      'not before' => ['not before claim failed', TokenValidationException::R_NOT_YET_VALID],
      'algorithm' => ['algorithm refused', TokenValidationException::R_ALG_NOT_ALLOWED],
      'signature' => ['signature verification failed', TokenValidationException::R_BAD_SIGNATURE],
      'fallback' => ['unclassified token error', TokenValidationException::R_MALFORMED],
    ];
  }

  /**
   * @dataProvider logoutErrorProvider
   */
  public function testLogoutErrorsMapToPurposeSpecificReasons(string $message, string $reason): void {
    $mapped = TokenValidationException::fromOidcLogout(new InvalidTokenException($message));

    self::assertSame($reason, $mapped->reason);
    self::assertSame('OIDC logout-token validation failed', $mapped->getMessage());
  }

  /**
   * @return array<string, array{string, string}>
   */
  public function logoutErrorProvider(): array {
    return [
      'events' => ['events claim is invalid', TokenValidationException::R_LOGOUT_EVENTS_INVALID],
      'nonce' => ['nonce is prohibited', TokenValidationException::R_LOGOUT_NONCE_PROHIBITED],
      'subject' => ['either a "sub" or "sid" is required', TokenValidationException::R_LOGOUT_SUBJECT_MISSING],
      'fallback' => ['signature verification failed', TokenValidationException::R_BAD_SIGNATURE],
    ];
  }

  public function testValidatedClaimValueObjectsExposeTheirClaims(): void {
    $id = new IdTokenClaims('subject-1', [
      'sub' => 'subject-1',
      'sid' => 'session-1',
      'email' => 'person@example.org',
      'email_verified' => 'true',
    ]);
    self::assertSame('subject-1', $id->subject);
    self::assertSame('session-1', $id->claim('sid'));
    self::assertSame('subject-1', $id->all['sub']);
    self::assertSame(['person@example.org', TRUE], $id->email());

    $logout = new LogoutTokenClaims('subject-1', 'session-1', 'token-1', ['jti' => 'token-1']);
    self::assertSame('subject-1', $logout->subject);
    self::assertSame('session-1', $logout->sessionId);
    self::assertSame('token-1', $logout->tokenId);
    self::assertSame(['jti' => 'token-1'], $logout->all);
  }

  public function testUntypedApiValuesAreNarrowedWithoutUnsafeCasts(): void {
    self::assertSame('text', Value::str('text'));
    self::assertSame('42', Value::str(42));
    self::assertSame('fallback', Value::str([], 'fallback'));
    self::assertSame('text', Value::nullableStr('text'));
    self::assertNull(Value::nullableStr(''));
    self::assertSame(42, Value::int('42'));
    self::assertSame(7, Value::int([], 7));
    self::assertSame(42, Value::nullableInt(42.9));
    self::assertNull(Value::nullableInt('not-a-number'));
    self::assertTrue(Value::bool(TRUE));
    self::assertTrue(Value::bool('yes'));
    self::assertFalse(Value::bool('no'));
    self::assertTrue(Value::bool(1));
    self::assertTrue(Value::bool([], TRUE));
    self::assertSame(['0' => 'zero', 'name' => 'value'], Value::row([0 => 'zero', 'name' => 'value']));
    self::assertSame([], Value::row('not-a-row'));
    self::assertSame(['a', 'b'], Value::strings(['a', '', 2, 'b', 'a']));
    self::assertSame([], Value::strings('not-a-list'));
    self::assertSame([1, 2], Value::ints(['1', 2, 'bad', 1]));
    self::assertSame([], Value::ints('not-a-list'));
  }

  public function testTheDefaultHttpClientCanBeRestoredAfterAnOverride(): void {
    $override = new \Symfony\Component\HttpClient\MockHttpClient();
    Http::setClient($override);
    self::assertSame($override, Http::client());

    Http::setClient(NULL);
    self::assertNotSame($override, Http::client());
  }

}
