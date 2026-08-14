<?php

declare(strict_types = 1);

namespace Civi\Warden\Tests\Unit;

use Civi\Warden\Tests\Support\IdTokenValidatorContract;

/**
 * The adversarial ID-token suite as a pure unit test — no CiviCRM, no database,
 * milliseconds to run. The same contract also runs in the headless suite so CI
 * gates it.
 *
 * @group unit
 * @covers \Civi\Warden\IdTokenValidator
 * @covers \Civi\Warden\ValidationPolicy
 * @covers \Civi\Warden\IdTokenClaims
 * @covers \Civi\Warden\TokenValidationException
 */
final class IdTokenValidatorTest extends IdTokenValidatorContract {}
