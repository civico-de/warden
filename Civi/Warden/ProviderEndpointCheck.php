<?php

declare(strict_types = 1);

namespace Civi\Warden;

use CRM_Warden_ExtensionUtil as E;
use DigitalCz\OpenIDConnect\Config\IssuerMetadata;
use DigitalCz\OpenIDConnect\Util\SignatureAlgorithmsFactory;

/**
 * What a usable provider publishes: its discovery document, the signing
 * algorithms it advertises and its signing key set.
 */
final class ProviderEndpointCheck {

  /**
   * @return list<\CRM_Utils_Check_Message>
   */
  public static function messages(Provider $provider): array {
    try {
      $discovery = OidcClient::metadataFor($provider);
    }
    catch (\Throwable $e) {
      return [new \CRM_Utils_Check_Message(
        'warden_discovery_' . $provider->id,
        E::ts('Discovery for provider "%1" is failing: %2', [
          1 => $provider->name,
          2 => htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'),
        ]),
        E::ts('warden: identity provider unreachable'),
        $provider->mode === Options::MODE_REQUIRED ? \Psr\Log\LogLevel::CRITICAL : \Psr\Log\LogLevel::ERROR,
        'fa-plug',
      )];
    }

    return [...self::checkAlgorithmOverlap($provider, $discovery), ...self::checkKeySet($provider)];
  }

  /**
   * Compare Warden's allow-list with both provider metadata and the asymmetric
   * algorithms available in the installed OIDC library.
   *
   * @return list<\CRM_Utils_Check_Message>
   */
  private static function checkAlgorithmOverlap(Provider $provider, IssuerMetadata $discovery): array {
    $messages = [];
    $supportedAlgorithms = SignatureAlgorithmsFactory::asymmetricAlgorithmNames();

    $unsupported = array_values(array_filter(
      $provider->allowedAlgorithms,
      static fn (string $alg): bool => !in_array($alg, $supportedAlgorithms, TRUE),
    ));
    if ($unsupported !== []) {
      $messages[] = new \CRM_Utils_Check_Message(
        'warden_alg_unsupported_' . $provider->id,
        E::ts(
          'Provider "%1" allows %2, which the installed OIDC library cannot verify. Every login with such a token will fail. Configure the provider to sign with one of: %3.',
          [
            1 => $provider->name,
            2 => htmlspecialchars(implode(', ', $unsupported), ENT_QUOTES, 'UTF-8'),
            3 => implode(', ', $supportedAlgorithms),
          ],
        ),
        E::ts('warden: signing algorithm not supported by this CiviCRM'),
        \Psr\Log\LogLevel::ERROR,
        'fa-shield',
      );
    }

    $signingAlgorithms = $discovery->idTokenSigningAlgValuesSupported();
    if ($signingAlgorithms === []) {
      return $messages;
    }

    $overlap = array_intersect($provider->allowedAlgorithms, $signingAlgorithms);
    if ($overlap === []) {
      $messages[] = new \CRM_Utils_Check_Message(
        'warden_alg_mismatch_' . $provider->id,
        E::ts(
          'Provider "%1" advertises id_token_signing_alg_values_supported = %2, but warden only allows %3. No token can satisfy both, so every login will be refused with alg_not_allowed.',
          [
            1 => $provider->name,
            2 => htmlspecialchars(implode(', ', $signingAlgorithms), ENT_QUOTES, 'UTF-8'),
            3 => htmlspecialchars(implode(', ', $provider->allowedAlgorithms), ENT_QUOTES, 'UTF-8'),
          ],
        ),
        E::ts('warden: signing algorithm mismatch'),
        \Psr\Log\LogLevel::ERROR,
        'fa-shield',
      );
    }

    $methods = $discovery->claims()['code_challenge_methods_supported'] ?? [];
    if (is_array($methods) && $methods !== [] && !in_array('S256', $methods, TRUE)) {
      $messages[] = new \CRM_Utils_Check_Message(
        'warden_no_pkce_' . $provider->id,
        E::ts(
          'Provider "%1" does not advertise S256 in code_challenge_methods_supported. warden sends PKCE regardless, but the provider may be ignoring it — check whether the client is registered as a public client that requires PKCE.',
          [1 => $provider->name],
        ),
        E::ts('warden: provider does not advertise PKCE'),
        \Psr\Log\LogLevel::NOTICE,
        'fa-shield',
      );
    }

    return $messages;
  }

  /**
   * Fetch the signing key set through the cache token verification uses.
   *
   * @return list<\CRM_Utils_Check_Message>
   */
  private static function checkKeySet(Provider $provider): array {
    try {
      OidcClient::jwksFor($provider);
    }
    catch (\Throwable $e) {
      return [
        new \CRM_Utils_Check_Message(
          'warden_jwks_' . $provider->id,
          E::ts('The signing key set of provider "%1" cannot be used, so no login through it can be verified: %2', [
            1 => $provider->name,
            2 => htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'),
          ]),
          E::ts('warden: signing keys unusable'),
          $provider->mode === Options::MODE_REQUIRED ? \Psr\Log\LogLevel::CRITICAL : \Psr\Log\LogLevel::ERROR,
          'fa-key',
        ),
      ];
    }

    return [];
  }

}
