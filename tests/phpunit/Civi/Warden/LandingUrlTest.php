<?php

declare(strict_types = 1);

namespace Civi\Warden;

use Civi\Warden\Tests\Support\LandingUrlContract;

/**
 * The same contract inside the headless suite, so CI gates it.
 *
 * Not a HeadlessInterface test: these classes need no database, and
 * CiviTestListener leaves a plain TestCase alone.
 *
 * @covers \Civi\Warden\LandingUrl
 */
final class LandingUrlTest extends LandingUrlContract {

  public function testAbsoluteUsesTheConfiguredBaseAndStillSanitises(): void {
    $absolute = LandingUrl::absolute('https://attacker.example.org');

    self::assertStringEndsWith(LandingUrl::DEFAULT_PATH, $absolute);
  }

}
