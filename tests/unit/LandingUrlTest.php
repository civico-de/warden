<?php

declare(strict_types = 1);

namespace Civi\Warden\Tests\Unit;

use Civi\Warden\LandingUrl;
use PHPUnit\Framework\TestCase;

/**
 * Open-redirect defence on the login route.
 *
 * @group unit
 * @covers \Civi\Warden\LandingUrl
 */
final class LandingUrlTest extends TestCase {

  /**
   * @dataProvider hostileDestinations
   */
  public function testHostileDestinationsFallBackToTheDefault(string $candidate, string $why): void {
    self::assertSame(LandingUrl::DEFAULT_PATH, LandingUrl::sanitise($candidate), $why);
  }

  /**
   * @return array<string, array{0: string, 1: string}>
   */
  public static function hostileDestinations(): array {
    return [
      'absolute https' => ['https://evil.example.org/', 'an absolute URL is a redirect off-site'],
      'absolute http' => ['http://evil.example.org/', 'an absolute URL is a redirect off-site'],
      'protocol relative' => ['//evil.example.org/', 'browsers resolve // against the current scheme'],
      'protocol relative with path' => ['//evil.example.org/civicrm/home', 'still off-site'],
      'backslash pair' => ['\\\\evil.example.org', 'several browsers normalise backslashes to slashes'],
      'mixed slash backslash' => ['/\\evil.example.org', 'normalises to //evil.example.org'],
      'javascript' => ['javascript:alert(1)', 'a script URL is not a path'],
      'data' => ['data:text/html,<script>alert(1)</script>', 'a data URL is not a path'],
      'traversal' => ['/../../etc/passwd', 'traversal'],
      'traversal to origin' => ['/civicrm/../..//evil.example.org', 'traversal that escapes the origin'],
      'newline smuggling' => ["/civicrm/home\nLocation: https://evil.example.org", 'header injection'],
      'null byte' => ["/civicrm/home\0", 'control characters'],
      'tab' => ["/civicrm\t/home", 'control characters'],
      'leading space' => [' https://evil.example.org', 'trimmed then still absolute'],
      'relative without slash' => ['civicrm/home', 'a bare relative path is ambiguous'],
      'empty' => ['', 'nothing to go on'],
    ];
  }

  /**
   * @dataProvider goodDestinations
   */
  public function testSiteRelativePathsSurvive(string $candidate): void {
    self::assertSame($candidate, LandingUrl::sanitise($candidate));
  }

  /**
   * @return array<string, array{0: string}>
   */
  public static function goodDestinations(): array {
    return [
      'home' => ['/civicrm/home?reset=1'],
      'a search' => ['/civicrm/contact/search?reset=1'],
      'with fragment' => ['/civicrm/dashboard#tab'],
      'root' => ['/'],
    ];
  }

  public function testNullIsTheDefault(): void {
    self::assertSame(LandingUrl::DEFAULT_PATH, LandingUrl::sanitise(NULL));
  }

}
