---
title: Betrieb
order: 20
---

# Betrieb

## Single Logout

### Abmelden in CiviCRM

Veröffentlicht der Anbieter einen `end_session_endpoint`, leitet die Abmeldung aus CiviCRM darüber, sodass auch die Sitzung beim Anbieter endet. Warden sendet `id_token_hint` und, wenn der Anbieter einen `login_hint`-Claim ausgestellt hat, `logout_hint`, damit der Anbieter die Kontoauswahl überspringen kann.

### Abmelden beim Anbieter

Für die Gegenrichtung registrieren Sie beim Anbieter die Back-Channel-Logout-URL von Warden und lassen ihn die Sitzungskennung (`sid`) mitsenden:

```text
https://IHR-CIVICRM/civicrm/warden/logout/backchannel
```

Der Anbieter schickt Warden dann ein signiertes Logout-Token. Warden prüft Signatur und Claims, lehnt ein bereits gesehenes Token ab und markiert die passende CiviCRM-Sitzung als widerrufen. Diese Sitzung endet bei ihrer nächsten Anfrage, bevor die angeforderte Seite läuft, nicht schon im Moment, in dem das Token eintrifft.

Warden speichert nur Hashes der lokalen Sitzung, des Subjekts und der Sitzung beim Anbieter. Sitzungsbindungen, die seit `warden_session_retention_days` nicht mehr gesehen wurden, löscht der tägliche Job; eine ältere Sitzung lässt sich vom Anbieter aus nicht mehr beenden.

Front-Channel-Logout unterstützt Warden nicht. Dieser Ablauf läuft in einem seitenübergreifenden Frame, in dem Browser das CiviCRM-Sitzungscookie nicht mitsenden. Eine Abmeldung aus einer anderen Anwendung erreicht Warden nur, wenn der Anbieter Back-Channel-Logout unterstützt.

## Statusprüfungen

Warden meldet seine Befunde auf der Seite System Status von CiviCRM (**Administer → Administration Console → System Status**). Jeder Befund hat einen festen Namen, sodass ein Monitoring über den API-Aufruf `System.check` ihn verfolgen und eine Administratorin ihn ausblenden kann. Ein Befund zu einem Anbieter endet auf dessen ID, zum Beispiel `warden_discovery_3`.

| Name | Befund | Schweregrad |
|---|---|---|
| `warden_discovery_<id>` | Das Discovery-Dokument lässt sich nicht abrufen | Fehler; kritisch bei einem Anbieter im Modus `required` |
| `warden_jwks_<id>` | Der Satz der Signaturschlüssel lässt sich nicht abrufen oder ist leer | Fehler; kritisch bei einem Anbieter im Modus `required` |
| `warden_no_pkce_<id>` | Der Anbieter kündigt PKCE mit `S256` nicht an; Warden sendet PKCE trotzdem | Hinweis |
| `warden_no_algorithms_<id>` | Der Anbieter erlaubt keinen Signaturalgorithmus | Fehler |
| `warden_alg_mismatch_<id>` | Keiner der erlaubten Algorithmen ist einer, mit dem der Anbieter signiert | Fehler |
| `warden_alg_unsupported_<id>` | Ein erlaubter Algorithmus kann von der mitgelieferten OpenID-Connect-Bibliothek nicht geprüft werden | Fehler |
| `warden_plaintext_secret_<id>` | Das Client-Secret ist unverschlüsselt gespeichert | kritisch |
| `warden_unreadable_secret_<id>` | Das Client-Secret lässt sich nicht entschlüsseln | kritisch |
| `warden_unknown_roles_<id>` | Die Rollenzuordnung nennt Rollen, die es nicht gibt | Warnung |
| `warden_cred_key_missing` | Kein `CIVICRM_CRED_KEYS` konfiguriert | Warnung; kritisch, sobald ein Anbieter ein Secret hat |
| `warden_insecure_session_cookie` | Dem Sitzungscookie fehlt das Flag `Secure`, typischerweise hinter einem Proxy, der TLS beendet | Fehler |
| `warden_redirect_uri` | Aus der Website-URL ergibt sich keine brauchbare Callback-URL | Warnung |
| `warden_disabled_by_constant` | `CIVICRM_WARDEN_DISABLE` ist definiert, Warden ist also abgeschaltet | Warnung |

Für einen Anbieter, dessen Issuer auf Microsoft Entra ID zeigt, kommen drei Prüfungen hinzu: `warden_entra_tenant_issuer_<id>` (der Issuer ist nicht mandantenspezifisch, Fehler), `warden_entra_email_link_<id>` (die Verknüpfung über E-Mail ist eingeschaltet, obwohl Entra keine bestätigte E-Mail zusichern kann, Warnung) und `warden_entra_groups_<id>` (die Rollenzuordnung nutzt `groups` statt App-Rollen, Warnung).

Eine Prüfung, die nicht laufen kann, meldet unter ihrem eigenen Namen einen Fehler mit dem Grund, statt zu schweigen. `warden_providers` bedeutet, dass sich die Liste der Anbieter selbst nicht lesen ließ; `warden_provider_<id>`, dass die Prüfungen eines Anbieters fehlgeschlagen sind.

## Anmeldeprotokoll

CiviCRM Standalone protokolliert keine Anmeldungen, deshalb führt Warden ein eigenes Protokoll unter **Single sign-on (warden) → Login trail**. Jede Zeile enthält den Anbieter, den Benutzer, sofern einer ermittelt wurde, das Ereignis, einen maschinenlesbaren Grund wie `bad_signature` oder `unknown_subject`, die IP-Adresse der Anfrage und die Uhrzeit.

Erfasste Ereignisse: Anmeldung erfolgreich, Anmeldung fehlgeschlagen, Anmeldung durch Richtlinie abgelehnt, Benutzer angelegt, Neuverknüpfung abgelehnt, Anfragen begrenzt, Abmeldung, Back-Channel-Abmeldung und widerrufene Sitzung beendet.

Das Protokoll enthält nie Tokens, Autorisierungscodes, E-Mail-Adressen oder Anzeigenamen. Das Subjekt wird als gesalzener Hash gespeichert; damit lassen sich die Zeilen einer Identität zuordnen, ohne sie preiszugeben. Zeilen lassen sich über die API weder ändern noch löschen und bleiben erhalten, wenn ihr Anbieter oder Benutzer gelöscht wird.

## Aufbewahrung

IP-Adressen sind personenbezogene Daten, deshalb wird das Protokoll nicht ewig aufbewahrt. Der tägliche geplante Job „Warden: prune the login trail“ löscht

- Zeilen des Anmeldeprotokolls, die älter als `warden_audit_retention_days` sind (Standard 180), und
- Sitzungsbindungen, die seit `warden_session_retention_days` nicht genutzt wurden (Standard 30).

Stellen Sie beide Werte so ein, wie es Ihre Datenschutzregeln erlauben.

## Begrenzung von Anmeldeversuchen

CiviCRM Standalone schützt nicht vor massenhaften Anmeldeversuchen. Warden zählt fehlgeschlagene Anmeldungen, Ablehnungen durch Richtlinien und abgelehnte Neuverknüpfungen je IP-Adresse und sperrt seine Anmelde- und Callback-Routen, sobald innerhalb von `warden_rate_limit_window` (Standard 300 Sekunden) `warden_rate_limit_attempts` (Standard 20) erreicht ist. Erfolgreiche Anmeldungen zählen nicht mit, ein ausgelastetes Büro hinter einer gemeinsamen Adresse wird also nicht gebremst.

Lässt sich die Adresse des Clients nicht ermitteln, etwa hinter einem Proxy, der sie verbirgt, lässt die Begrenzung die Anfrage durch.
