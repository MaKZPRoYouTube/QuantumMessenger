# Quantum Messenger (Android Studio template)

Шаблон Android-проекта для безопасного мессенджера с фокусом на:
- гибридный обмен ключами: X25519 + ML-KEM (Kyber/liboqs),
- fail-closed стратегию (нет тихого downgrade без PQC),
- PFS-подобную модель через цепочки ключей (ratchet basis),
- hardening endpoint и конфигурации Android.

## Что реализовано
1. Полный Android Studio/Gradle проект (скрипты `gradlew`/`gradlew.bat` в репозитории).
2. `HybridSessionManager` на HKDF-SHA256:
   - объединяет классический и постквантовый секрет,
   - выводит `rootKey`, `sendingChainKey`, `receivingChainKey`.
3. Реальный X25519 key agreement (`X25519KeyAgreementProvider`).
4. `LiboqsMlKemProvider` с `isAvailable()` и fail-closed логикой.
5. `SecureMessageRatchet`:
   - derivation message key per message,
   - AES-GCM encryption/decryption с AAD.
6. Android hardening:
   - `FLAG_SECURE`,
   - backup/device-transfer exclusions,
   - cleartext off + `network_security_config`.
7. Unit-тесты для ротации сессий и ratchet roundtrip.


## Быстрый запуск (чтобы проект собирался как "готовый")
1. Установите Android SDK (Platform 34 + Build-Tools) и задайте путь в `local.properties`:
   ```properties
   sdk.dir=/absolute/path/to/Android/Sdk
   ```
2. Сгенерируйте `gradle-wrapper.jar` (если отсутствует в вашей платформе/репозитории):
   ```bash
   gradle wrapper --gradle-version 8.14.3
   ```
3. После этого запускайте:
   ```bash
   ./gradlew --version
   ./gradlew testDebugUnitTest
   ```
4. Для production-режима PQC добавьте `liboqsbridge.so` в APK для нужного ABI (`arm64-v8a`, и т.д.).
   - Если бинарник отсутствует, приложение блокирует гибридную сессию (fail-closed).
   - В debug-режиме включается локальный тестовый fallback, чтобы не блокировать разработку.

## Что обязательно доделать до production
- Подключить реальный JNI bridge к `liboqs` (ML-KEM-768/1024).
- Заменить demo-часть X25519 на сетевой pre-key protocol с аутентикацией peer keys.
- Реализовать полноценный Double Ratchet (DH ratchet + skipped keys handling).
- Добавить слой сокрытия метаданных (Tor/I2P/mixnet).
- Внедрить endpoint hardening (attestation, anti-tamper, root detection).
- Провести внешний криптоаудит и pentest.

## Важно
Абсолютно «невзламываемого» мессенджера не существует. Этот проект — серьёзная инженерная база, но не финальный production-продукт без пунктов выше.
