---
title: Konfiguration
order: 10
---

# Konfiguration

Alles liegt unter **Administer → Single sign-on (warden)**: Identitätsanbieter, verknüpfte Identitäten, das Anmeldeprotokoll und die Einstellungen. Für die Konfiguration braucht es die Berechtigung `administer warden`, siehe [Berechtigungen](reference.md#berechtigungen).

## Felder eines Anbieters

| Feld | Standard | Bedeutung |
|---|---|---|
| Name | — | Maschinenname. Er steht in jeder Zeile des Anmeldeprotokolls; eine Umbenennung trennt die Verbindung zum bisherigen Verlauf. |
| Label | — | Text auf dem Anmeldeknopf. |
| Issuer | — | Die Issuer-URL. Warden hängt `/.well-known/openid-configuration` an; der `issuer` im abgerufenen Dokument muss exakt mit diesem Wert übereinstimmen. Jeder Issuer kann nur zu einem Anbieter gehören. |
| Client ID | — | Wie beim Anbieter registriert. |
| Client secret | leer | Wird mit `CIVICRM_CRED_KEYS` verschlüsselt gespeichert. Leer lassen für einen öffentlichen Client, der nur PKCE nutzt. |
| Scopes | `openid profile email` | Durch Leerzeichen getrennt. `openid` wird immer gesendet. |
| Mode | `optional` | Siehe [Modi](#modi). |
| Allowed signing algorithms | `RS256` | Durch Leerzeichen getrennte Liste der erlaubten Werte im `alg`-Header des ID-Tokens. |
| Enabled | ja | Ein deaktivierter Anbieter wird vollständig ignoriert. |
| Order | 1 | Reihenfolge der Anmeldeknöpfe. |
| Claim to role map | leer | Siehe [Rollenzuordnung](#rollenzuordnung). |
| Role sync | `provision_only` | Siehe [Rollenzuordnung](#rollenzuordnung). |
| Profile sync | `off` | Siehe [Profilabgleich](#profilabgleich). |
| Provisioning | `never` | Siehe [Wer sich anmelden darf](#wer-sich-anmelden-darf). |
| Unmatched-subject linking | `never` | Siehe [Wer sich anmelden darf](#wer-sich-anmelden-darf). |
| Roles for provisioned users | leer | Durch Leerzeichen getrennte Rollennamen für neu angelegte Benutzer. Leer bedeutet: Der Benutzer kann sich anmelden, aber nichts tun. |

## Modi

- `disabled`: Der Anbieter ist konfiguriert, aber niemand kann sich darüber anmelden.
- `optional`: ein Knopf neben dem Passwortformular.
- `required`: Anmeldung und Zurücksetzen mit Passwort werden auf der ganzen Website verweigert. Das Passwortformular bleibt sichtbar, funktioniert aber nicht. Lesen Sie [Schutz vor Aussperrung](index.md#schutz-vor-aussperrung), bevor Sie diesen Modus einschalten.

## Wer sich anmelden darf

Warden erkennt eine Person am Issuer und am `sub`-Claim des Anbieters, nie an einer E-Mail-Adresse allein. Bei jeder Anmeldung entscheidet Warden in dieser Reihenfolge:

1. **Das Subjekt ist bereits verknüpft** mit einem CiviCRM-Benutzer: Dieser Benutzer wird angemeldet. Ein deaktivierter Benutzer wird abgewiesen.
2. **Unbekanntes Subjekt, eine andere Extension kennt die Person**: Eine Extension, die auf das Event `civi.warden.resolveUser` hört, kann den zu verknüpfenden Benutzer nennen oder die Anmeldung ablehnen, siehe [Events](reference.md#events).
3. **Unbekanntes Subjekt, Verknüpfung auf `verified_email`**: Warden übernimmt einen bestehenden Benutzer, dessen Benutzername oder Anmeldeadresse mit dem `email`-Claim übereinstimmt, und nur, wenn der Anbieter `email_verified: true` bestätigt. Das birgt die Gefahr einer Kontoübernahme, wenn beim Anbieter unbestätigte Adressen eingetragen werden können; empfohlen ist `never`.
4. **Unbekanntes Subjekt, Anlegen auf `provision`**: Warden legt einen Benutzer mit den Rollen aus „Roles for provisioned users“ an. Der Benutzername besteht aus einem lesbaren Teil aus `preferred_username` (oder dem Namen des Anbieters) und einem kurzen, aus Issuer und Subjekt abgeleiteten Anhang, damit er eindeutig und stabil bleibt.
5. **Sonst** wird die Anmeldung abgewiesen und im Anmeldeprotokoll vermerkt.

Bestehende Verknüpfungen stehen unter **Linked identities**. Wird ein CiviCRM-Benutzer gelöscht, verschwinden auch seine Verknüpfungen.

## Rollenzuordnung

Die Rollenzuordnung (Claim to role map) ist ein JSON-Objekt, das einen Claim nennt und die CiviCRM-Rollen, die jeder seiner Werte verleiht:

```json
{
  "claim": "realm_access.roles",
  "map": {
    "crm-admin": ["admin"],
    "crm-staff": ["staff"]
  }
}
```

Die Zuordnung ist eine Positivliste: Nicht aufgeführte Claim-Werte verleihen nichts, und rechts stehen nur Namen von CiviCRM-Rollen, nie Berechtigungen.

Role sync legt fest, wann die Zuordnung angewendet wird:

| Role sync | Verhalten |
|---|---|
| `off` | Rollen werden nur in CiviCRM verwaltet. |
| `provision_only` | Die zugeordneten Rollen werden einmal vergeben, wenn der Benutzer angelegt wird. |
| `every_login` | Bei jeder Anmeldung werden zugeordnete Rollen hinzugefügt und entfernt, bis sie dem Claim entsprechen. Rollen außerhalb der Zuordnung bleiben unberührt. |

## Profilabgleich

Warden schreibt die Namens-Claims des Anbieters (`given_name`, `family_name`, oder ersatzweise `name` in den Vornamen) und einen bestätigten `email`-Claim in den Kontakt, wenn es einen Benutzer anlegt oder übernimmt. Steht Profile sync auf `every_login`, hält Warden sie bei jeder späteren Anmeldung aktuell: Die Namensfelder folgen den Claims, und die Adresse wird zur primären E-Mail des Kontakts, hochgestuft, wenn der Kontakt sie schon hat, sonst hinzugefügt; die bisherige primäre Adresse bleibt als weitere Adresse erhalten. Die E-Mail wird nur geschrieben, solange der Anbieter `email_verified: true` bestätigt.

Die Anmeldeadresse schreibt Warden nicht selbst. Ob eine neue primäre E-Mail sie mitzieht, entscheidet die CiviCRM-Einstellung `syncCMSEmail` (standardmäßig an); CiviCRM überspringt eine Adresse, die schon ein anderer Benutzer hat. Passwort-Zurücksetzungen gehen an die Anmeldeadresse; bei eingeschaltetem Abgleich lässt sich ein lokales Passwort also über die bestätigte Adresse des Anbieters anfordern. Schalten Sie `syncCMSEmail` aus, wenn diese Adresse fest bleiben muss. Eine fehlgeschlagene Aktualisierung weist die Anmeldung ab und steht im Protokoll als `profile_sync_failed`.

Bei den meisten Anbietern können Menschen ihren Namen selbst ändern. Schalten Sie den Profilabgleich nur ein, wenn der Anbieter für Kontaktnamen auf dieser Website maßgeblich ist.

## Microsoft Entra ID

Legen Sie in Entra ID eine App-Registrierung für einen einzelnen Mandanten vom Typ **Web** an und tragen Sie den Callback von Warden als exakte Umleitungs-URI ein:

```text
https://IHR-CIVICRM/civicrm/warden/return
```

Konfigurieren Sie den Anbieter so:

- Issuer: `https://login.microsoftonline.com/DIRECTORY-TENANT-ID/v2.0`, wobei `DIRECTORY-TENANT-ID` die GUID des Mandanten ist. Verwenden Sie nicht `common`, `organizations`, eine Mandanten-Domain, die URL des Discovery-Dokuments oder einen abschließenden Schrägstrich. Warden akzeptiert genau einen Issuer, keine mandantenübergreifenden Issuer-Vorlagen von Microsoft.
- Client ID: die Anwendungs-ID (Client-ID) der App-Registrierung.
- Client secret: ein gültiger geheimer Wert aus **Zertifikate & Geheimnisse**.
- Scopes `openid profile email`, erlaubter Signaturalgorithmus `RS256`.
- Lassen Sie **Unmatched-subject linking** auf `never`. Die Werte `email` und `preferred_username` in Entra sind änderbar, und Entra sendet die für die Verknüpfung nötige Bestätigung `email_verified` nicht.

Für die Berechtigungen sind Entra-**App-Rollen** vorzuziehen. Legen Sie Werte wie `CiviCRM.Staff` an, weisen Sie ihnen in der Unternehmensanwendung Benutzer oder Gruppen zu und ordnen Sie den Claim `roles` zu:

```json
{
  "claim": "roles",
  "map": {
    "CiviCRM.Admin": ["admin"],
    "CiviCRM.Staff": ["staff"]
  }
}
```

Eine Zuordnung über den Claim `groups` mit Gruppen-Objekt-IDs funktioniert ebenfalls, aber Entra lässt diesen Claim weg, wenn jemand zu vielen Gruppen angehört. Warden fragt die fehlenden Gruppen nicht bei Microsoft Graph ab. Es weist die Anmeldung ab, statt den fehlenden Claim als „keine Rollen“ zu lesen.

Die Abmeldung aus CiviCRM beendet auch die Entra-Sitzung. Eine Abmeldung, die in einer anderen an Entra angeschlossenen Anwendung beginnt, beendet die CiviCRM-Sitzung nicht, denn Entra bietet das nur über Front-Channel-Logout an, das Warden nicht unterstützt, siehe [Single Logout](operations.md#single-logout).

Microsoft beschreibt die [mandantenspezifischen OpenID-Connect-Endpunkte](https://learn.microsoft.com/de-de/entra/identity-platform/v2-protocols-oidc), die [Claims im ID-Token](https://learn.microsoft.com/de-de/entra/identity-platform/id-token-claims-reference) und [Gruppen-Claims und ihre Obergrenze](https://learn.microsoft.com/de-de/entra/identity-platform/optional-claims).
