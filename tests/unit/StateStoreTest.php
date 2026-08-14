<?php

declare(strict_types = 1);

namespace Civi\Warden\Tests\Unit;

use Civi\Warden\Tests\Support\StateStoreContract;

/**
 * Pure unit run of the shared contract: no CiviCRM, no database.
 *
 * @group unit
 * @covers \Civi\Warden\StateStore
 */
final class StateStoreTest extends StateStoreContract {}
