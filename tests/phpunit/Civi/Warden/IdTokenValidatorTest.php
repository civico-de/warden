<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Warden\Tests\Support\IdTokenValidatorContract;

/**
 * The adversarial ID-token suite, run inside the headless suite so CI gates it.
 *
 * Deliberately NOT a HeadlessInterface test: the validator has no CiviCRM
 * dependency and needs no database, so making it one would trade seconds of
 * runtime for nothing. CiviTestListener leaves a plain TestCase alone.
 *
 * The cases live in the shared contract, which tests/unit runs too — one table,
 * two harnesses, no duplication to drift.
 *
 * @covers \Civi\Warden\IdTokenValidator
 * @covers \Civi\Warden\ValidationPolicy
 * @covers \Civi\Warden\IdTokenClaims
 * @covers \Civi\Warden\TokenValidationException
 */
final class IdTokenValidatorTest extends IdTokenValidatorContract {
}
