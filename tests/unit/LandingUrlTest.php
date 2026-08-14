<?php

declare(strict_types = 1);

namespace Civi\Warden\Tests\Unit;

use Civi\Warden\Tests\Support\LandingUrlContract;

/**
 * Pure unit run of the shared contract: no CiviCRM, no database.
 *
 * @group unit
 * @covers \Civi\Warden\LandingUrl
 */
final class LandingUrlTest extends LandingUrlContract {}
