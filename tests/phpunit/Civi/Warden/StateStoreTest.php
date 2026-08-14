<?php

declare(strict_types = 1);

namespace Civi\Warden;

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
}
