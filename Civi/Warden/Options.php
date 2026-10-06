<?php

declare(strict_types = 1);

namespace Civi\Warden;

use CRM_Warden_ExtensionUtil as E;

/**
 * Pseudoconstant callbacks. Every method is static and takes no arguments so
 * core can cache the option list.
 */
final class Options {

  public const MODE_DISABLED = 'disabled';
  public const MODE_OPTIONAL = 'optional';
  public const MODE_REQUIRED = 'required';

  public const PROVISION_NEVER = 'never';
  public const PROVISION_ON = 'provision';

  public const LINK_NEVER = 'never';
  public const LINK_VERIFIED_EMAIL = 'verified_email';

  public const ROLE_SYNC_OFF = 'off';
  public const ROLE_SYNC_PROVISION = 'provision_only';
  public const ROLE_SYNC_EVERY_LOGIN = 'every_login';

  public const PROFILE_SYNC_OFF = 'off';
  public const PROFILE_SYNC_EVERY_LOGIN = 'every_login';

  public const EVENT_LOGIN_SUCCESS = 'login_success';
  public const EVENT_LOGIN_FAILURE = 'login_failure';
  public const EVENT_LOGIN_DENIED = 'login_denied';
  public const EVENT_PROVISIONED = 'provisioned';
  public const EVENT_RELINK_REFUSED = 'relink_refused';
  public const EVENT_RATE_LIMITED = 'rate_limited';
  public const EVENT_LOGOUT = 'logout';
  public const EVENT_BACKCHANNEL_LOGOUT = 'backchannel_logout';
  public const EVENT_SESSION_REVOKED = 'session_revoked';

  /**
   * @return array<string, string>
   */
  public static function modes(): array {
    return [
      self::MODE_DISABLED => E::ts('Disabled - the provider is configured but no login is possible'),
      self::MODE_OPTIONAL => E::ts('Optional - a button beside the password form'),
      self::MODE_REQUIRED => E::ts('Required - password login is denied site-wide'),
    ];
  }

  /**
   * @return array<string, string>
   */
  public static function provisionPolicies(): array {
    return [
      self::PROVISION_NEVER => E::ts('Never - an unknown subject is refused'),
      self::PROVISION_ON => E::ts('Create a user on first login'),
    ];
  }

  /**
   * @return array<string, string>
   */
  public static function linkPolicies(): array {
    return [
      self::LINK_NEVER => E::ts('Never link by email (recommended)'),
      self::LINK_VERIFIED_EMAIL => E::ts('Adopt an existing user when email_verified is true'),
    ];
  }

  /**
   * @return array<string, string>
   */
  public static function roleSyncModes(): array {
    return [
      self::ROLE_SYNC_OFF => E::ts('Off - roles are managed in CiviCRM'),
      self::ROLE_SYNC_PROVISION => E::ts('At provisioning only'),
      self::ROLE_SYNC_EVERY_LOGIN => E::ts('On every login - mapped roles are added AND removed'),
    ];
  }

  /**
   * @return array<string, string>
   */
  public static function profileSyncModes(): array {
    return [
      self::PROFILE_SYNC_OFF => E::ts('Off - the contact is written at provisioning only'),
      self::PROFILE_SYNC_EVERY_LOGIN => E::ts('On every login - name and verified email follow the provider'),
    ];
  }

  /**
   * @return array<string, string>
   */
  public static function auditEvents(): array {
    return [
      self::EVENT_LOGIN_SUCCESS => E::ts('Login succeeded'),
      self::EVENT_LOGIN_FAILURE => E::ts('Login failed'),
      self::EVENT_LOGIN_DENIED => E::ts('Login denied by policy'),
      self::EVENT_PROVISIONED => E::ts('User provisioned'),
      self::EVENT_RELINK_REFUSED => E::ts('Relink refused'),
      self::EVENT_RATE_LIMITED => E::ts('Rate limited'),
      self::EVENT_LOGOUT => E::ts('Logout'),
      self::EVENT_BACKCHANNEL_LOGOUT => E::ts('Back-channel logout'),
      self::EVENT_SESSION_REVOKED => E::ts('Revoked session terminated'),
    ];
  }

}
