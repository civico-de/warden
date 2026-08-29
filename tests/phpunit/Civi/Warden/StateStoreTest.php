<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Warden\Tests\Support\ArrayStateStorage;
use Civi\Warden\Tests\Support\StateStoreContract;

/**
 * The same contract inside the headless suite, so CI gates it.
 *
 * Not a HeadlessInterface test: these classes need no database, and
 * CiviTestListener leaves a plain TestCase alone.
 *
 * @covers \Civi\Warden\StateStore
 */
final class StateStoreTest extends StateStoreContract {

  public function testEmptyGeneratedStateIsRefused(): void {
    $store = new StateStore(new ArrayStateStorage('session'), 600);

    $this->expectException(\CRM_Core_Exception::class);
    $this->expectExceptionMessageMatches('/empty OIDC state/');
    $store->remember('', ['nonce' => 'n']);
  }

  public function testRememberWithoutSessionFailsClosed(): void {
    $store = new StateStore(new ArrayStateStorage(''), 600);

    $this->expectException(\CRM_Core_Exception::class);
    $this->expectExceptionMessageMatches('/without a session/');
    $store->remember('state', ['nonce' => 'n']);
  }

  public function testConsumeWithoutSessionFailsClosed(): void {
    $storage = new ArrayStateStorage('session');
    $store = new StateStore($storage, 600);
    $state = $store->create(['nonce' => 'n']);
    $storage->sessionId = '';

    self::assertNull($store->consume($state));
  }

}
