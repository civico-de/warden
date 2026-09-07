<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * Client-secret handling.
 *
 * Core's `crypto.token` degrades silently: without `CIVICRM_CRED_KEYS` the
 * default registry "encrypts" with a plaintext key and nothing warns.
 * `protect()` throws instead, so the write fails loudly.
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
   * Is a real CRED key configured? The plaintext key is registered
   * unconditionally, so the question is whether the winning one is a cipher.
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
   * Decrypt a stored client secret. NULL means stored but unreadable (lost
   * or rotated key); does not throw so the provider screen still opens.
   */
  public static function reveal(?string $stored): ?string {
    if ($stored === NULL || $stored === '') {
      return '';
    }

    try {
      return Value::str(self::token()->decrypt($stored, ['CRED', 'plain']));
    }
    catch (\Throwable) {
      return NULL;
    }
  }

  /**
   * Is this stored value ciphertext, or plaintext wearing a token wrapper?
   */
  public static function isProtected(?string $stored): bool {
    if ($stored === NULL || $stored === '') {
      return TRUE;
    }

    // The `plain` suite returns the input untouched, so only the delimiter test tells.
    try {
      return !self::token()->isPlainText($stored);
    }
    catch (\Throwable) {
      return FALSE;
    }
  }

}
