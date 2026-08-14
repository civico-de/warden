<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * Where a user is sent after a successful login.
 *
 * `CRM_Utils_System::redirect()` does no validation whatsoever, and Standalone's
 * own login form already forwards an unvalidated `originalUrl`. A login
 * endpoint that echoes a caller-supplied destination is an open redirect, and
 * an open redirect on the login route is a phishing primitive: the victim sees
 * the real site, authenticates for real, and is handed to the attacker.
 *
 * So warden accepts one shape only — a site-relative path — and normalises
 * everything else to the home page. Pure, and tested against the usual
 * bypasses.
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

    // Control characters, spaces and DEL are how a payload is smuggled past a
    // naive prefix check; a real path has none. Tested on the RAW string and
    // before anything else, because trim() strips NUL — so trimming first
    // would quietly erase exactly the byte this rejects.
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
   * The sanitised path as an absolute URL on this site.
   *
   * Built from CIVICRM_UF_BASEURL rather than the request, for the same reason
   * the redirect_uri is — see RedirectUri.
   */
  public static function absolute(?string $candidate): string {
    $base = rtrim(Value::str(\CRM_Utils_Constant::value('CIVICRM_UF_BASEURL')), '/');

    return $base . self::sanitise($candidate);
  }

}
