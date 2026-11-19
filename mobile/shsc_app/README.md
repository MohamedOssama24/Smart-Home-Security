# SHSC — app mobile (Flutter)

App Android/iOS di Smart Home Security Check (Milestone 14). Documentazione completa: [docs/23-MOBILE-APP.md](../../docs/23-MOBILE-APP.md).

- `lib/core`: client API (`dio`, rotazione del refresh token), sessione, push FCM, provider Riverpod.
- `lib/ui`: schermate (login, abitazioni, dashboard, dispositivi, scansioni, avvisi).
- `lib/l10n`: testi IT/EN (`gen-l10n`).
- `test`: test unit e widget, flusso integrato su HTTP; `integration_test`: lo stesso flusso su dispositivo.

Flutter gira in Docker (immagine `ghcr.io/cirruslabs/flutter:3.44.0`):

```
docker run --rm -v "<repo>/mobile/shsc_app:/work" -w /work ghcr.io/cirruslabs/flutter:3.44.0 bash -c "flutter pub get && flutter test"
```

Build: `flutter build apk --dart-define=SHSC_API_BASE_URL=https://<dominio>`. Push opzionale con `SHSC_FIREBASE_API_KEY`, `SHSC_FIREBASE_APP_ID`, `SHSC_FIREBASE_SENDER_ID` e `SHSC_FIREBASE_PROJECT_ID`.

Tutti i dati dei test sono `[MOCK]`.
