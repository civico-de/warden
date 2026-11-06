---
title: Referenz
order: 30
---

# Referenz

## Berechtigungen

| Berechtigung | Erlaubt |
|---|---|
| `administer warden` | Anbieter, Identitätsverknüpfungen und Einstellungen konfigurieren. Wer sie hat, kann einem Subjekt eines Anbieters Zugang zu jedem Konto geben. Enthalten in `administer CiviCRM`. |
| `view warden log` | Das Anmeldeprotokoll lesen, ohne die Konfiguration ändern zu können. Enthalten in `administer warden`. |

## Einstellungen

Unter **Single sign-on (warden) → Settings**:

| Einstellung | Standard | Bedeutung |
|---|---|---|
| `warden_enabled` | an | Hauptschalter. Aus: Warden verweigert seine Anmelde- und Callback-Routen und erzwingt keinen Modus; die Anmeldung mit Passwort funktioniert weiter. |
| `warden_protect_admin_password_login` | an | Im Modus `required` behalten Benutzer mit `administer CiviCRM` Anmeldung und Zurücksetzen mit Passwort. |
| `warden_discovery_ttl` | 900 s | Wie lange das Discovery-Dokument und die Signaturschlüssel zwischengespeichert werden, begrenzt auf 300–3600. Ein fehlgeschlagener Abruf wird nur 60 Sekunden gespeichert. |
| `warden_clock_leeway` | 60 s | Toleranz für Uhrzeitabweichungen bei `exp`, `iat` und `nbf`, begrenzt auf 0–300. |
| `warden_state_ttl` | 600 s | Wie lange der Browser Zeit hat, vom Anbieter zurückzukehren, begrenzt auf 60–1800. |
| `warden_rate_limit_attempts` | 20 | Erlaubte Fehlversuche je IP-Adresse innerhalb des Zeitfensters. 0 schaltet die Begrenzung ab. |
| `warden_rate_limit_window` | 300 s | Zeitfenster der Begrenzung, begrenzt auf 30–3600. |
| `warden_audit_retention_days` | 180 | Alter, ab dem Zeilen des Anmeldeprotokolls gelöscht werden. |
| `warden_session_retention_days` | 30 | Alter, ab dem ungenutzte Sitzungsbindungen gelöscht werden. Mindestens so lang wie die längste PHP-Sitzungsdauer halten. |

Die Konstante `CIVICRM_WARDEN_DISABLE` mit einem wahren Wert in `civicrm.settings.php` hat Vorrang vor `warden_enabled` und lässt sich über die Oberfläche nicht aufheben.

## URLs

| Pfad | Zweck |
|---|---|
| `civicrm/warden/return` | Die beim Anbieter zu registrierende Callback-URL. |
| `civicrm/warden/logout/backchannel` | Die Back-Channel-Logout-URL, siehe [Single Logout](operations.md#single-logout). |
| `civicrm/warden/login` | Startet eine Anmeldung; die Knöpfe auf der Anmeldeseite zeigen hierher. |

## Geplanter Job

„Warden: prune the login trail“ läuft täglich und ruft die API-Aktion `Warden.prune` auf. Er löscht, was die beiden Aufbewahrungseinstellungen oben erlauben, siehe [Aufbewahrung](operations.md#aufbewahrung).

## Events

Eine andere Extension kann über zwei Symfony-Events auf `Civi::dispatcher()` an einer Anmeldung mitwirken. Jedes trägt ein Event-Objekt aus dem Namensraum `Civi\Warden\Event`. `provider` ist ein `Civi\Warden\Provider` und `claims` ein `Civi\Warden\IdTokenClaims`, beide nur lesbar.

| Event | Wann | Eigenschaften |
|---|---|---|
| `civi.warden.resolveUser` (`ResolveUserEvent`) | Ein geprüftes Token nennt ein Subjekt, das mit keinem Benutzer verknüpft ist, bevor Verknüpfung über E-Mail und Anlegen versucht werden. | `provider`, `claims`, `userId` (auf eine bestehende Benutzer-ID setzen, um diesen Benutzer zu verknüpfen und anzumelden), `refusal` (auf einen kurzen Grund setzen, um die Anmeldung abzulehnen; er steht im Protokoll als `refused_by_listener`). |
| `civi.warden.postLogin` (`PostLoginEvent`) | Die CiviCRM-Sitzung besteht und das Protokoll hat seine Zeile `login_success`. | `provider`, `claims`, `userId`, `isNewUser`. |

Ein bereits verknüpftes Subjekt erreicht `resolveUser` nie; ein Listener kann eine bestehende Verknüpfung also nicht überschreiben. Ein von einem Listener genannter Benutzer wird trotzdem abgewiesen, wenn das Konto nicht existiert, deaktiviert ist oder bei diesem Anbieter schon mit einem anderen Subjekt verknüpft ist.

Ein Listener ist eine Vertrauensentscheidung: Er läuft für jeden Anbieter und vor dessen Verknüpfungsregel, kann also auch bei einem Anbieter mit Verknüpfung `never` ein Konto verknüpfen. Prüfen Sie `$e->provider`, bevor Sie zuordnen. Schreiben Sie in `refusal` einen Grundcode, keine personenbezogenen Daten, denn er landet im Anmeldeprotokoll. Eine Exception aus einem `resolveUser`-Listener weist die Anmeldung mit einer allgemeinen Meldung ab und steht im Protokoll als `listener_failed`; eine Exception aus `postLogin` wird geloggt und macht die Anmeldung nicht rückgängig.

```php
use Civi\Warden\Event\ResolveUserEvent;

Civi::dispatcher()->addListener(ResolveUserEvent::NAME, function (ResolveUserEvent $e) {
  // Only the provider this directory is the authority for.
  if ($e->provider->name !== 'staff_directory') {
    return;
  }
  $userId = MyDirectory::userIdFor($e->claims->claim('employee_id'));
  if ($userId !== NULL) {
    $e->userId = $userId;
  }
});
```

## Sicherheitsmodell

- Autorisierungsanfragen sind kurzlebige Einträge zur einmaligen Verwendung mit zufälligem State, Nonce und PKCE-Verifier.
- ID-Tokens werden erst angenommen, wenn Issuer, Audience, Signatur und Zeit-Claims gegen die veröffentlichten Signaturschlüssel des Anbieters geprüft sind.
- Back-Channel-Logout-Tokens werden genauso geprüft, über ihre `jti` gegen Wiederverwendung gesichert und gehashten lokalen Sitzungsbindungen zugeordnet.
- Benutzer werden über das dauerhafte Paar aus Issuer und Subjekt verknüpft, nie über eine unbestätigte E-Mail-Adresse allein.
- Ein in CiviCRM deaktivierter Benutzer wird abgewiesen, auch wenn seine Identität verknüpft ist.
- Die Rollenzuordnung ist eine Positivliste von CiviCRM-Rollennamen; ein Anbieter kann keine Berechtigung nennen.

Eine Sicherheitslücke melden Sie bitte per E-Mail an security@civico.de, nicht in einem öffentlichen Issue.
