<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * Client-secret handling.
 *
 * Core's `crypto.token` degrades silently: `CryptoRegistry::createDefaultRegistry()`
 * always registers a plaintext key tagged CRED at weight 32768, so on a site
 * with no `CIVICRM_CRED_KEYS` an `encrypt()` call still succeeds and still
 * returns a token — one whose "cipher" is the identity function. Nothing warns
 * and nothing throws; the secret is simply sitting in the database in the
 * clear, next to a column named `client_secret` that everybody will assume is
 * encrypted.
 *
 * warden refuses that trade. `protect()` throws when no real key is
 * configured, so the write fails loudly instead of producing a database row
 * that lies about itself, and StatusCheck reports the same condition before
 * anybody tries.
 */
final class Secret {

  private static function registry(): \Civi\Crypto\CryptoRegistry {
    /** @var \Civi\Crypto\CryptoRegistry */
    return \Civi::service('crypto.registry');
  }

  private static function token(): \Civi\Crypto\CryptoToken {
    /** @var \Civi\Crypto\CryptoToken */
    return \Civi::service('crypto.token');
  }

  /**
   * Is a real CRED key configured?
   *
   * The plaintext key is registered unconditionally, so the question is not
   * "is there a CRED key" but "is the one we would get an actual cipher".
   */
  public static function keyAvailable(): bool {
    try {
      $key = self::registry()->findKey('CRED');
    }
    catch (\Throwable) {
      return FALSE;
    }

    return Value::str($key['suite'] ?? NULL, 'plain') !== 'plain';
  }

  /**
   * Encrypt a client secret for storage.
   *
   * @throws \CRM_Core_Exception
   *   When no real CRED key is configured. Deliberately fatal to the write:
   *   see the class docblock.
   */
  public static function protect(string $plaintext): string {
    if ($plaintext === '') {
      return '';
    }

    if (!self::keyAvailable()) {
      throw new \CRM_Core_Exception(
        'warden refuses to store a client secret because this site has no encryption key. '
        . 'Define CIVICRM_CRED_KEYS in civicrm.settings.php (for example '
        . "define('CIVICRM_CRED_KEYS', 'aes-cbc:hkdf-sha256:' . 'a-long-random-string');) "
        . 'and reload, then save the provider again. '
        . 'Without it CiviCRM would "encrypt" with a no-op cipher and the secret would be readable to anyone with database access.',
      );
    }

    return Value::str(self::token()->encrypt($plaintext, 'CRED'));
  }

  /**
   * Decrypt a stored client secret.
   *
   * Reading stays tolerant: a site that lost its key after a bad restore must
   * still be able to open the provider screen and see what is wrong, and rows
   * written before this rule existed must not become unreadable.
   */
  public static function reveal(?string $stored): string {
    if ($stored === NULL || $stored === '') {
      return '';
    }

    try {
      return Value::str(self::token()->decrypt($stored, ['CRED', 'plain']));
    }
    catch (\Throwable) {
      return '';
    }
  }

  /**
   * Is this stored value ciphertext, or plaintext wearing a token wrapper?
   *
   * Used by the status check to tell an operator that a specific provider
   * needs re-saving after they configure a key, rather than only that the key
   * is missing.
   */
  public static function isProtected(?string $stored): bool {
    if ($stored === NULL || $stored === '') {
      return TRUE;
    }

    // With the `plain` suite CryptoToken::encrypt() returns the input
    // untouched — no wrapper, no marker — so the only way to tell ciphertext
    // from a bare secret is the delimiter test the class exposes itself.
    try {
      return !self::token()->isPlainText($stored);
    }
    catch (\Throwable) {
      return FALSE;
    }
  }

}
