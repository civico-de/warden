<?php

declare(strict_types = 1);

namespace Civi\Warden;

use CRM_Warden_ExtensionUtil as E;

/**
 * Operator diagnostics for the optional Microsoft Entra provider profile.
 */
final class EntraStatusCheck {

  /**
   * @return list<\CRM_Utils_Check_Message>
   */
  public static function messages(Provider $provider): array {
    if (!Entra::matches($provider->issuer)) {
      return [];
    }

    $messages = [];
    if (Entra::tenantId($provider->issuer) === NULL) {
      $messages[] = self::issuerMessage($provider);
    }
    if ($provider->linkPolicy === Options::LINK_VERIFIED_EMAIL) {
      $messages[] = self::emailMessage($provider);
    }
    if ($provider->roleClaim === 'groups') {
      $messages[] = self::groupsMessage($provider);
    }

    return $messages;
  }

  private static function issuerMessage(Provider $provider): \CRM_Utils_Check_Message {
    return new \CRM_Utils_Check_Message(
      'warden_entra_tenant_issuer_' . $provider->id,
      E::ts(
        'Microsoft Entra provider "%1" must use the tenant-specific v2 issuer <code>https://login.microsoftonline.com/&lt;Directory tenant ID&gt;/v2.0</code>. Do not use common, organizations, consumers, a tenant domain, a discovery-document URL, or a trailing slash: warden validates the discovered and token issuers byte for byte.',
        [1 => $provider->name],
      ),
      E::ts('warden: Entra issuer is not tenant-specific'),
      \Psr\Log\LogLevel::ERROR,
      'fa-cloud',
    );
  }

  private static function emailMessage(Provider $provider): \CRM_Utils_Check_Message {
    return new \CRM_Utils_Check_Message(
      'warden_entra_email_link_' . $provider->id,
      E::ts(
        'Microsoft Entra ID does not provide the standard email_verified assertion warden requires for automatic account adoption. Provider "%1" will therefore never link an existing user by email. Keep linking set to never and provision or link identities explicitly.',
        [1 => $provider->name],
      ),
      E::ts('warden: Entra email linking is unavailable'),
      \Psr\Log\LogLevel::WARNING,
      'fa-link',
    );
  }

  private static function groupsMessage(Provider $provider): \CRM_Utils_Check_Message {
    return new \CRM_Utils_Check_Message(
      'warden_entra_groups_' . $provider->id,
      E::ts(
        'Provider "%1" maps Entra group object IDs. Entra omits the groups claim when a user exceeds its token limit; warden then refuses the login rather than silently removing roles, and it deliberately does not call Microsoft Graph during authentication. Prefer Entra App Roles and map the top-level roles claim.',
        [1 => $provider->name],
      ),
      E::ts('warden: prefer Entra App Roles over groups'),
      \Psr\Log\LogLevel::WARNING,
      'fa-users',
    );
  }

}
