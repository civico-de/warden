<?php

declare(strict_types = 1);

namespace Civi\Warden\Subscriber;

use Civi\Api4\WardenIdentity;
use Civi\Core\Event\GenericHookEvent;
use Civi\Core\Service\AutoSubscriber;

/**
 * Removing identity links when their user is deleted.
 *
 * This replaces the `ON DELETE CASCADE` that WardenIdentity.user_id cannot
 * carry as a real foreign key — `User` is standaloneusers' table, and the
 * schema generator resolves references against warden's own entities when it
 * builds in isolation.
 *
 * It is a correctness requirement, not tidiness. An orphan row still names a
 * subject and a user id; if that id were ever handed to a different account —
 * after a restore, a re-import, or an AUTO_INCREMENT reset — the orphan would
 * quietly log its subject in as somebody else.
 *
 * Audit rows are deliberately NOT deleted. The trail records that a login
 * happened; erasing it because the account was later removed would defeat the
 * point of keeping one. The user id is nulled so nothing dangles.
 */
final class UserCleanupSubscriber extends AutoSubscriber {

  /**
   * @return array<string, mixed>
   */
  public static function getSubscribedEvents(): array {
    return ['hook_civicrm_post' => ['onPost', 0]];
  }

  public static function onPost(GenericHookEvent $event): void {
    if (($event->objectName ?? NULL) !== 'User' || ($event->op ?? NULL) !== 'delete') {
      return;
    }

    $id = $event->id ?? NULL;
    if (!is_numeric($id)) {
      return;
    }
    $userId = (int) $id;

    try {
      WardenIdentity::delete(FALSE)->addWhere('user_id', '=', $userId)->execute();
      \CRM_Core_DAO::executeQuery(
        'UPDATE civicrm_warden_audit SET user_id = NULL WHERE user_id = %1',
        [1 => [$userId, 'Integer']],
      );
    }
    catch (\Throwable $e) {
      // Loud: an identity row that outlives its user is the exact condition
      // this listener exists to prevent, so a failure must not be silent.
      \Civi::log()->error('warden: could not clean up after user {id} was deleted: {msg}', [
        'id' => $userId,
        'msg' => $e->getMessage(),
      ]);
    }
  }

}
