<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Warden\Tests\Support\RoleMapperContract;

/**
 * The same contract inside the headless suite, so CI gates it.
 *
 * Not a HeadlessInterface test: these classes need no database, and
 * CiviTestListener leaves a plain TestCase alone.
 *
 * @covers \Civi\Warden\RoleMapper
 * @covers \Civi\Warden\Claims
 * @covers \Civi\Warden\Provider
 * @covers \Civi\Warden\Value
 */
final class RoleMapperTest extends RoleMapperContract {}
