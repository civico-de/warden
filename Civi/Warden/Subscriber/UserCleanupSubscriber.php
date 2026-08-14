<?php

declare(strict_types = 1);

namespace Civi\Warden\Subscriber;

use Civi\Api4\WardenIdentity;
use Civi\Core\Event\PostEvent;
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

  public static function onPost(PostEvent $event): void {
    // PostEvent names these `entity` and `action`, NOT `objectName` and `op`.
    if ($event->entity !== 'User' || $event->action !== 'delete') {
      return;
    }

    if (!is_numeric($event->id)) {
      return;
    }
    $userId = (int) $event->id;

    try {
      WardenIdentity::delete(FALSE)->addWhere('user_id', '=', $userId)->execute();
      // WardenAudit::update() would load and rewrite every matching row inside
      // the delete's own transaction; one statement is both correct and cheap.
      // ckconform-ignore raw-sql -- bulk NULL-out during a user delete
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
