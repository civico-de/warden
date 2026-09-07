<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * Where a user is sent after a successful login.
 *
 * An open redirect on the login route is a phishing primitive, so only a
 * site-relative path is accepted; everything else becomes the home page.
 */
final class LandingUrl {

  public const DEFAULT_PATH = '/civicrm/home?reset=1';

  /**
   * @param string|null $candidate
   *   Untrusted input, typically the `land` query parameter.
   */
  public static function sanitise(?string $candidate): string {
    $candidate = (string) $candidate;
    if ($candidate === '') {
      return self::DEFAULT_PATH;
    }

    // Control characters, spaces and DEL smuggle payloads past prefix checks.
    // Tested on the RAW string: trim() would strip the NUL this rejects.
    if (preg_match('/[\x00-\x20\x7F]/', $candidate) === 1) {
      return self::DEFAULT_PATH;
    }

    // Backslashes: several browsers treat \\evil.example as //evil.example.
    if (str_contains($candidate, '\\')) {
      return self::DEFAULT_PATH;
    }

    // Must be a path, not a URL. This rejects https://evil, //evil (protocol
    // relative) and javascript:/data: in one test.
    if (!str_starts_with($candidate, '/') || str_starts_with($candidate, '//')) {
      return self::DEFAULT_PATH;
    }

    // No traversal, and no way to reach a different origin through one.
    if (str_contains($candidate, '..')) {
      return self::DEFAULT_PATH;
    }

    return $candidate;
  }

  /**
   * The sanitised path as an absolute URL, built from CIVICRM_UF_BASEURL (see RedirectUri).
   */
  public static function absolute(?string $candidate): string {
    $base = rtrim(Value::str(\CRM_Utils_Constant::value('CIVICRM_UF_BASEURL')), '/');

    return $base . self::sanitise($candidate);
  }

}
