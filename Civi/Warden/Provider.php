<?php

declare(strict_types = 1);

namespace Civi\Warden;

// @mago-expect lint:cyclomatic-complexity -- the branches are the validation
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
  // @mago-expect lint:excessive-parameter-list -- a readonly value object, single caller
  private function __construct(
    public readonly int $id,
    public readonly string $name,
    public readonly string $label,
    public readonly string $issuer,
    public readonly string $clientId,
    #[\SensitiveParameter]
    public readonly string $clientSecret,
    public readonly string $scopes,
    public readonly string $mode,
    public readonly array $allowedAlgorithms,
    public readonly string $roleClaim,
    public readonly array $roleMap,
    public readonly string $roleSyncMode,
    public readonly string $profileSyncMode,
    public readonly string $provisionPolicy,
    public readonly string $linkPolicy,
    public readonly array $defaultRoleNames,
    public readonly bool $isActive,
    public readonly bool $secretUnreadable,
  ) {}

  /**
   * @param array<string, mixed> $row
   *   A WardenProvider row as APIv4 returns it.
   */
  public static function fromArray(array $row): self {
    $map = self::decodeRoleMap($row['claim_role_map'] ?? NULL);
    $secret = Secret::reveal(Value::nullableStr($row['client_secret'] ?? NULL));

    return new self(
      Value::int($row['id'] ?? NULL),
      Value::str($row['name'] ?? NULL),
      Value::str($row['label'] ?? NULL),
      Value::str($row['issuer'] ?? NULL),
      Value::str($row['client_id'] ?? NULL),
      $secret ?? '',
      self::normaliseScopes($row['scopes'] ?? NULL),
      Value::str($row['mode'] ?? NULL, Options::MODE_DISABLED),
      self::parseAlgorithms(Value::str($row['allowed_algorithms'] ?? NULL, 'RS256')),
      $map['claim'],
      $map['map'],
      Value::str($row['role_sync_mode'] ?? NULL, Options::ROLE_SYNC_PROVISION),
      Value::str($row['profile_sync_mode'] ?? NULL, Options::PROFILE_SYNC_OFF),
      Value::str($row['provision_policy'] ?? NULL, Options::PROVISION_NEVER),
      Value::str($row['link_policy'] ?? NULL, Options::LINK_NEVER),
      self::words($row['default_role_names'] ?? NULL),
      Value::bool($row['is_active'] ?? NULL),
      $secret === NULL,
    );
  }

  /**
   * The issuer as configured, which is also what the ID token's `iss` must be.
   *
   * OIDC Discovery requires the discovered `issuer` to equal this value
   * byte-for-byte, so once Discovery has checked it there is only one issuer
   * string in play. In particular, `/tenant` and `/tenant/` are distinct.
   */
  public function issuerForComparison(): string {
    return $this->issuer;
  }

  public function usable(): bool {
    return (
      $this->isActive
      && $this->mode !== Options::MODE_DISABLED
      && $this->issuer !== ''
      && $this->clientId !== ''
      && $this->allowedAlgorithms !== []
      && !$this->secretUnreadable
    );
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
      $names = Value::strings(is_array($roles) ? $roles : [$roles]);
      if ($names !== []) {
        $clean[$claimValue] = $names;
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
  private static function parseAlgorithms(?string $raw): array {
    $parts = preg_split('/[\s,]+/', strtoupper(trim((string) $raw))) ?: [];

    return array_values(array_filter($parts, static fn (string $algorithm): bool => $algorithm !== ''));
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
