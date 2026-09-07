<?php

declare(strict_types = 1);

namespace Civi\Warden\Subscriber;

use Civi\Api4\WardenIdentity;
use Civi\Api4\WardenSession;
use Civi\Core\Event\PreEvent;
use Civi\Core\Service\AutoSubscriber;

/**
 * Removing identity links when their user is deleted.
 *
 * Replaces the `ON DELETE CASCADE` WardenIdentity.user_id cannot carry as a
 * real FK (`User` is standaloneusers' table). An orphan row would log its
 * subject in as whoever gets the recycled user id. Audit rows are kept with
 * the user id nulled.
 */
final class UserCleanupSubscriber extends AutoSubscriber {

  /**
   * @return array<string, mixed>
   */
  public static function getSubscribedEvents(): array {
    return ['hook_civicrm_pre' => ['onPre', 0]];
  }

  public static function onPre(PreEvent $event): void {
    // Pre-delete: a cleanup failure must abort the deletion.
    if ($event->entity !== 'User' || $event->action !== 'delete') {
      return;
    }

    if (!is_numeric($event->id)) {
      return;
    }
    $userId = (int) $event->id;

    WardenIdentity::delete(FALSE)->addWhere('user_id', '=', $userId)->execute();
    WardenSession::delete(FALSE)->addWhere('user_id', '=', $userId)->execute();
    // ckconform-ignore raw-sql -- bulk NULL-out during a user delete
    \CRM_Core_DAO::executeQuery(
      'UPDATE civicrm_warden_audit SET user_id = NULL WHERE user_id = %1',
      [1 => [$userId, 'Integer']],
    );
  }

}
