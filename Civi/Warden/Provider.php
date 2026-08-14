<?php

declare(strict_types = 1);

namespace Civi\Warden;

/**
 * A configured provider as the flow sees it: typed, with the JSON columns
 * already decoded and the secret already revealed. Built by ProviderRepository;
 * never constructed from user input directly.
 */
final class Provider {

  /**
   * @param list<string> $allowedAlgorithms
   * @param list<string> $defaultRoleNames
   * @param array<string, list<string>> $roleMap
   *   Claim value => list of CiviCRM role names.
   */
  private function __construct(
    public readonly int $id,
    public readonly string $name,
    public readonly string $label,
    public readonly string $issuer,
    public readonly string $clientId,
    public readonly string $clientSecret,
    public readonly string $scopes,
    public readonly string $mode,
    public readonly array $allowedAlgorithms,
    public readonly string $roleClaim,
    public readonly array $roleMap,
    public readonly string $roleSyncMode,
    public readonly string $provisionPolicy,
    public readonly string $linkPolicy,
    public readonly array $defaultRoleNames,
    public readonly bool $isActive,
  ) {}

  /**
   * @param array<string, mixed> $row
   *   A WardenProvider row as APIv4 returns it.
   */
  public static function fromArray(array $row): self {
    $map = self::decodeRoleMap($row['claim_role_map'] ?? NULL);

    return new self(
      (int) ($row['id'] ?? 0),
      (string) ($row['name'] ?? ''),
      (string) ($row['label'] ?? ''),
      rtrim((string) ($row['issuer'] ?? ''), '/'),
      (string) ($row['client_id'] ?? ''),
      Secret::reveal(is_string($row['client_secret'] ?? NULL) ? $row['client_secret'] : NULL),
      self::normaliseScopes($row['scopes'] ?? NULL),
      (string) ($row['mode'] ?? Options::MODE_DISABLED),
      ValidationPolicy::parseAlgorithms(is_string($row['allowed_algorithms'] ?? NULL) ? $row['allowed_algorithms'] : 'RS256'),
      $map['claim'],
      $map['map'],
      (string) ($row['role_sync_mode'] ?? Options::ROLE_SYNC_PROVISION),
      (string) ($row['provision_policy'] ?? Options::PROVISION_NEVER),
      (string) ($row['link_policy'] ?? Options::LINK_NEVER),
      self::words($row['default_role_names'] ?? NULL),
      (bool) ($row['is_active'] ?? FALSE),
    );
  }

  /**
   * The issuer as configured, which is also what the ID token's `iss` must be.
   *
   * OIDC Discovery requires the discovered `issuer` to equal this value
   * exactly, so once Discovery has checked it there is only one issuer string
   * in play. Trailing slashes are trimmed on both sides because operators
   * paste them and providers do not send them.
   */
  public function issuerForComparison(): string {
    return $this->issuer;
  }

  public function usable(): bool {
    return $this->isActive
      && $this->mode !== Options::MODE_DISABLED
      && $this->issuer !== ''
      && $this->clientId !== ''
      && $this->allowedAlgorithms !== [];
  }

  /**
   * @return array{claim: string, map: array<string, list<string>>}
   */
  private static function decodeRoleMap(mixed $raw): array {
    $empty = ['claim' => '', 'map' => []];
    if (!is_string($raw) || trim($raw) === '') {
      return $empty;
    }

    $decoded = json_decode($raw, TRUE);
    if (!is_array($decoded)) {
      return $empty;
    }

    $claim = $decoded['claim'] ?? '';
    $map = $decoded['map'] ?? [];
    if (!is_string($claim) || !is_array($map)) {
      return $empty;
    }

    $clean = [];
    /** @var mixed $roles */
    foreach ($map as $claimValue => $roles) {
      if (!is_string($claimValue) || $claimValue === '') {
        continue;
      }
      $names = [];
      /** @var mixed $role */
      foreach ((array) $roles as $role) {
        if (is_string($role) && $role !== '') {
          $names[] = $role;
        }
      }
      if ($names !== []) {
        $clean[$claimValue] = array_values(array_unique($names));
      }
    }

    return ['claim' => $claim, 'map' => $clean];
  }

  private static function normaliseScopes(mixed $raw): string {
    $scopes = self::words($raw);
    if (!in_array('openid', $scopes, TRUE)) {
      array_unshift($scopes, 'openid');
    }

    return implode(' ', $scopes);
  }

  /**
   * @return list<string>
   */
  private static function words(mixed $raw): array {
    if (!is_string($raw)) {
      return [];
    }
    $parts = preg_split('/[\s,]+/', trim($raw)) ?: [];

    return array_values(array_unique(array_filter($parts, static fn (string $p): bool => $p !== '')));
  }

}
