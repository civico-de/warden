<?php

declare(strict_types = 1);

namespace Civi\Warden\Tests\Unit;

use Civi\Warden\StateStore;
use Civi\Warden\Tests\Support\ArrayStateStorage;
use PHPUnit\Framework\TestCase;

/**
 * @group unit
 * @covers \Civi\Warden\StateStore
 */
final class StateStoreTest extends TestCase {

  private function store(ArrayStateStorage $storage, int $ttl = 600): StateStore {
    return new StateStore($storage, $ttl);
  }

  public function testARoundTripReturnsThePayload(): void {
    $storage = new ArrayStateStorage('session-a');
    $store = $this->store($storage);

    $state = $store->create(['nonce' => 'n1', 'code_verifier' => 'v1', 'landing' => '/civicrm/home']);

    self::assertSame(
      ['nonce' => 'n1', 'code_verifier' => 'v1', 'landing' => '/civicrm/home'],
      $store->consume($state),
    );
  }

  public function testStateIsSingleUse(): void {
    // The replay defence: the same callback presented twice must not work
    // twice, which is what stops a captured code+token pair being reused.
    $storage = new ArrayStateStorage('session-a');
    $store = $this->store($storage);

    $state = $store->create(['nonce' => 'n1']);

    self::assertNotNull($store->consume($state));
    self::assertNull($store->consume($state), 'a state must not be redeemable twice');
  }

  public function testAnInvalidStateIsStillBurned(): void {
    // Presenting a state from the wrong session spends it, so an attacker
    // cannot probe and then let the victim complete the same flow.
    $storage = new ArrayStateStorage('session-a');
    $store = $this->store($storage);
    $state = $store->create(['nonce' => 'n1']);

    $storage->sessionId = 'session-b';
    self::assertNull($store->consume($state));

    $storage->sessionId = 'session-a';
    self::assertNull($store->consume($state), 'a state presented from the wrong session must not survive');
  }

  public function testStateFromAnotherSessionIsRefused(): void {
    $storage = new ArrayStateStorage('session-a');
    $store = $this->store($storage);
    $state = $store->create(['nonce' => 'n1']);

    $storage->sessionId = 'attacker-session';

    self::assertNull($store->consume($state));
  }

  /**
   * The ordering pin.
   *
   * State is bound to the session id that minted it, so consuming it BEFORE
   * the session is regenerated works and consuming it AFTER does not. This is
   * why LoginFlow consumes state first and only then calls
   * session_regenerate_id() + authx_login(); a callback that logged in first
   * would refuse every legitimate login, and "fixing" that by dropping the
   * binding would remove the defence.
   */
  public function testStateMustBeConsumedBeforeTheSessionIsRegenerated(): void {
    $storage = new ArrayStateStorage('pre-login-session');
    $store = $this->store($storage);
    $state = $store->create(['nonce' => 'n1']);

    // Right order: consume, then the session id changes.
    self::assertNotNull($store->consume($state), 'consuming before regeneration must succeed');
    $storage->sessionId = 'post-login-session';

    // Wrong order: regenerate first, then try to consume.
    $storage->sessionId = 'pre-login-session';
    $second = $store->create(['nonce' => 'n2']);
    $storage->sessionId = 'post-login-session';

    self::assertNull(
      $store->consume($second),
      'consuming after regeneration must fail — otherwise the session binding is not being enforced',
    );
  }

  public function testAnExpiredStateIsRefused(): void {
    $storage = new ArrayStateStorage('session-a');
    $store = $this->store($storage, 600);

    $created = 1_000_000;
    $state = $store->create(['nonce' => 'n1'], $created);

    self::assertNotNull($store->consume($state, $created + 599));

    $state2 = $store->create(['nonce' => 'n2'], $created);
    self::assertNull($store->consume($state2, $created + 601), 'a state past its TTL must not be redeemable');
  }

  public function testUnknownStateReturnsNull(): void {
    $store = $this->store(new ArrayStateStorage('session-a'));

    self::assertNull($store->consume('never-issued'));
  }

  public function testStatesAreBounded(): void {
    // A page that fires many login redirects must not grow the session without
    // limit; the oldest entries fall out.
    $storage = new ArrayStateStorage('session-a');
    $store = $this->store($storage);

    $first = $store->create(['n' => 0], 1000);
    for ($i = 1; $i <= 12; $i++) {
      $store->create(['n' => $i], 1000 + $i);
    }

    self::assertLessThanOrEqual(8, count($storage->states));
    self::assertNull($store->consume($first), 'the oldest state should have been evicted');
  }

  public function testStatesAreUnguessable(): void {
    $store = $this->store(new ArrayStateStorage('session-a'));

    $seen = [];
    for ($i = 0; $i < 50; $i++) {
      $state = $store->create(['n' => $i]);
      self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $state);
      $seen[$state] = TRUE;
    }

    self::assertCount(50, $seen, 'every state must be distinct');
  }

}
