---
title: Warden
---

# Warden

Mit Warden melden sich Menschen über einen OpenID-Connect-Identitätsanbieter wie Keycloak oder Microsoft Entra ID bei CiviCRM Standalone an. Warden verknüpft jeden CiviCRM-Benutzer mit dem dauerhaften Paar aus Aussteller (Issuer) und Subjekt des Anbieters, kann Benutzer bei ihrer ersten Anmeldung anlegen, ordnet Claims des Anbieters CiviCRM-Rollen zu und führt ein eigenes Anmeldeprotokoll.

Warden ist an keinen Hersteller gebunden: Jeder Anbieter durchläuft dieselbe Discovery, denselben Authorization-Code-Flow mit PKCE und dieselbe Prüfung des signierten ID-Tokens. Gedacht ist Warden für Organisationen, die die Konten ihrer Mitarbeitenden bereits in einem Identitätsanbieter verwalten und CiviCRM daran anschließen wollen.

## Voraussetzungen

- CiviCRM Standalone in der Version aus der `info.xml` der Extension oder neuer. Mit Drupal, WordPress oder anderen CMS-Integrationen funktioniert Warden nicht.
- PHP 8.4.
- Die Core-Extensions `standaloneusers`, `authx`, SearchKit und FormBuilder.
- Ein Schlüssel in `CIVICRM_CRED_KEYS`, damit Client-Secrets verschlüsselt gespeichert werden. Ohne Schlüssel speichert Warden kein Secret.

## Installation

Laden Sie das Release-Archiv von der [Release-Seite](https://github.com/civico-de/warden/releases). Es enthält seine Composer-Abhängigkeiten. Entpacken Sie es in das Extension-Verzeichnis von CiviCRM und aktivieren Sie es:

```bash
cv ext:enable warden
```

## Schnellstart

1. Konfigurieren Sie `CIVICRM_CRED_KEYS`.
2. Registrieren Sie beim Identitätsanbieter einen vertraulichen Client mit dieser Callback-URL:

    ```text
    https://IHR-CIVICRM/civicrm/warden/return
    ```

3. Öffnen Sie in CiviCRM **Administer → Single sign-on (warden) → Identity providers** und legen Sie den Anbieter mit Issuer-URL, Client-ID und Client-Secret an. Lassen Sie den Modus auf `optional`.
4. Melden Sie sich über den neuen Knopf auf der Anmeldeseite an. Eine unbekannte Person wird abgewiesen, bis Sie ihre Identität verknüpfen oder das Anlegen von Benutzern erlauben, siehe [Wer sich anmelden darf](configuration.md#wer-sich-anmelden-darf).
5. Prüfen Sie unter **Administer → Administration Console → System Status** die Meldungen von Warden und im Anmeldeprotokoll, was geschehen ist.

Stellen Sie einen Anbieter erst auf `required`, nachdem eine Anmeldung vollständig geklappt hat, und lesen Sie vorher den nächsten Abschnitt.

## Schutz vor Aussperrung

Ein falsch konfigurierter Anbieter im Modus `required` sperrt alle aus. Es gibt drei Wege zurück:

- Schalten Sie die Einstellung `warden_enabled` aus. Warden verweigert dann seine eigenen Anmelde- und Callback-Routen und erzwingt keinen Modus mehr, die Anmeldung mit Passwort funktioniert wieder.
- Definieren Sie in `civicrm.settings.php` die Konstante `CIVICRM_WARDEN_DISABLE` mit einem wahren Wert. Sie hat Vorrang vor der Einstellung, falls die Oberfläche nicht erreichbar ist.
- Deaktivieren Sie die Extension mit `cv ext:disable warden`.

Außerdem behalten Benutzer mit `administer CiviCRM` im Modus `required` standardmäßig die Anmeldung mit Passwort. Wer diesen Schutz abschaltet, macht den Identitätsanbieter zum einzigen Zugang; tun Sie das nur mit einem erprobten Notfallverfahren.

## Weitere Seiten

- [Konfiguration](configuration.md): Anbieter, Modi, wer sich anmelden darf, Rollenzuordnung, Profilabgleich und Microsoft Entra ID.
- [Betrieb](operations.md): Single Logout, Statusprüfungen, Anmeldeprotokoll, Aufbewahrung und Begrenzung von Anmeldeversuchen.
- [Referenz](reference.md): Berechtigungen, Einstellungen, URLs und Events für andere Extensions.
