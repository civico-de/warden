<?php

declare(strict_types = 1);

namespace Civi\Warden\Tests\Unit;

use Civi\Warden\Tests\Support\RoleMapperContract;

/**
 * Pure unit run of the shared contract: no CiviCRM, no database.
 *
 * @group unit
 * @covers \Civi\Warden\RoleMapper
 * @covers \Civi\Warden\Claims
 * @covers \Civi\Warden\Provider
 * @covers \Civi\Warden\Pkce
 * @covers \Civi\Warden\Value
 */
final class RoleMapperTest extends RoleMapperContract {}
