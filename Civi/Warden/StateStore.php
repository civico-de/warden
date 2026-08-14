<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * warden's own store for in-flight authorization requests.
 *
 * It does NOT use `Civi::service('oauth2.state')`. That service lives in the
 * bundled `oauth-client` extension, not in core (ext/oauth-client/Civi/OAuth/
 * OAuthState.php), and depending on it would drag in the whole stack whose
 * missing signature check, missing nonce and missing PKCE are the reason
 * warden exists. See docs/adr/0001-no-oauth-client.md.
 *
 * Three rules, all enforced here rather than by the caller:
 *
 * 1. SINGLE USE. `consume()` deletes before it returns. A replayed callback —
 *    the same code and the same ID token a second time — finds nothing, which
 *    is what makes nonce replay impossible rather than merely unlikely.
 * 2. BOUND TO THE SESSION. An entry created in one browser session cannot be
 *    redeemed from another. This is why the login flow must consume state
 *    BEFORE authx_login() regenerates the session id — see the ordering note
 *    on LoginFlow.
 * 3. EXPIRED IS GONE. Entries past their TTL are pruned on every access, so a
 *    tab left open overnight cannot be completed the next morning.
 */
final class StateStore {

  private const MAX_ENTRIES = 8;

  public function __construct(
    private readonly StateStorage $storage,
    private readonly int $ttl = 600,
  ) {}

  /**
   * @param array<string, mixed> $payload
   *   Whatever the callback will need: provider id, nonce, code_verifier,
   *   landing path.
   *
   * @return string
   *   The opaque `state` parameter to send to the provider.
   */
  public function create(array $payload, ?int $now = NULL): string {
    $now ??= time();
    $state = Random::urlSafe(32);

    $states = $this->prune($this->storage->read(), $now);

    // Bound so a page that fires many login redirects cannot grow the session
    // without limit. Oldest first out.
    if (count($states) >= self::MAX_ENTRIES) {
      uasort($states, static fn (array $a, array $b): int => (int) ($a['created'] ?? 0) <=> (int) ($b['created'] ?? 0));
      $states = array_slice($states, -(self::MAX_ENTRIES - 1), NULL, TRUE);
    }

    $states[$state] = [
      'created' => $now,
      'expires' => $now + $this->ttl,
      'session' => $this->storage->sessionId(),
      'payload' => $payload,
    ];
    $this->storage->write($states);

    return $state;
  }

  /**
   * Redeem a state exactly once.
   *
   * @return array<string, mixed>|null
   *   The stored payload, or NULL when the state is unknown, expired or was
   *   created in a different session. All three are indistinguishable to the
   *   caller on purpose — the audit reason is `unknown_state` either way.
   */
  public function consume(string $state, ?int $now = NULL): ?array {
    $now ??= time();
    $states = $this->prune($this->storage->read(), $now);

    $entry = $states[$state] ?? NULL;
    // Delete first, whatever happens next. A state that has been presented is
    // spent even if it turns out to be invalid.
    unset($states[$state]);
    $this->storage->write($states);

    if ($entry === NULL) {
      return NULL;
    }

    $boundSession = $entry['session'] ?? NULL;
    if (!is_string($boundSession) || !hash_equals($boundSession, $this->storage->sessionId())) {
      return NULL;
    }

    $payload = $entry['payload'] ?? NULL;

    /** @var array<string, mixed>|null $payload */
    return is_array($payload) ? $payload : NULL;
  }

  /**
   * @param array<string, array<string, mixed>> $states
   *
   * @return array<string, array<string, mixed>>
   */
  private function prune(array $states, int $now): array {
    return array_filter($states, static fn (array $e): bool => is_int($e['expires'] ?? NULL) && $e['expires'] > $now);
  }

}
