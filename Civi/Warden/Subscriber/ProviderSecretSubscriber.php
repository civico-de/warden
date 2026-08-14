<?php

declare(strict_types = 1);

namespace Civi\Warden\Subscriber;

use Civi\Core\Event\PreEvent;
use Civi\Core\Service\AutoSubscriber;
use Civi\Warden\Secret;
use Civi\Warden\Value;

// @mago-expect lint:cyclomatic-complexity
// Encrypt-or-refuse plus the activation guard; both are the same rule.
/**
 * Encrypting the client secret on the way into the database, and refusing the
 * write when that is not possible.
 *
 * This sits on `hook_civicrm_pre` rather than in the Afform or the API entity
 * so it covers every route that can write a provider — the admin form, an
 * APIv4 call, a managed record, a migration script. A rule that only the UI
 * enforces is not a rule.
 *
 * The refusal is the point. Core's `crypto.token` would happily "encrypt" with
 * a no-op cipher on a site with no CIVICRM_CRED_KEYS and return something that
 * looks like a token, leaving a readable secret in a column everyone assumes is
 * encrypted. warden fails the write instead, with a message naming the constant
 * to define.
 */
final class ProviderSecretSubscriber extends AutoSubscriber {

  /**
   * @return array<string, mixed>
   */
  public static function getSubscribedEvents(): array {
    return ['hook_civicrm_pre' => ['onPre', 0]];
  }

  /**
   * @throws \CRM_Core_Exception
   */
  public static function onPre(PreEvent $event): void {
    // PreEvent names these `entity` and `action`, NOT `objectName` and `op`
    // as the hook signature suggests. Reading the wrong property yields NULL
    // and the guard below then silently matches nothing at all.
    if ($event->entity !== 'WardenProvider') {
      return;
    }
    if ($event->action !== 'create' && $event->action !== 'edit') {
      return;
    }

    /** @var mixed $params */
    $params = $event->params;
    if (!is_array($params)) {
      return;
    }

    if (array_key_exists('client_secret', $params)) {
      $secret = $params['client_secret'];
      // Already ciphertext (a re-save that did not touch the field) is left
      // alone; encrypting twice would make it undecryptable.
      if (is_string($secret) && $secret !== '' && !Secret::isProtected($secret)) {
        // Throws when no real key is configured — that is the refusal.
        $event->params['client_secret'] = Secret::protect($secret);
      }
    }

    self::refuseActivationWithUnprotectedSecret($event, $event->action);
  }

  /**
   * A provider whose secret is sitting in the database unencrypted must not be
   * switched on, even if the row predates this rule.
   *
   * @throws \CRM_Core_Exception
   */
  private static function refuseActivationWithUnprotectedSecret(PreEvent $event, string $op): void {
    /** @var array<string, mixed> $params */
    $params = $event->params;
    if (!Value::bool($params['is_active'] ?? NULL)) {
      return;
    }
    if (Secret::keyAvailable()) {
      return;
    }

    // The secret being written now, or the one already stored.
    $secret = $params['client_secret'] ?? NULL;
    if (!is_string($secret) || $secret === '') {
      $id = $event->id;
      if ($op !== 'edit' || !is_numeric($id)) {
        return;
      }
      $row = \Civi\Api4\WardenProvider::get(FALSE)
        ->addSelect('client_secret')
        ->addWhere('id', '=', (int) $id)
        ->execute()
        ->first();
      $secret = is_array($row) && is_string($row['client_secret'] ?? NULL) ? $row['client_secret'] : '';
    }

    if ($secret === '' || Secret::isProtected($secret)) {
      return;
    }

    throw new \CRM_Core_Exception(
      'warden will not enable a provider whose client secret is stored unencrypted. '
      . 'Define CIVICRM_CRED_KEYS in civicrm.settings.php, re-save the provider so the secret is encrypted, and then enable it.',
    );
  }

}
