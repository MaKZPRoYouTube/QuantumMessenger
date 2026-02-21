# Quantum Messenger (Android Studio template)

Шаблон Android-проекта для безопасного мессенджера с фокусом на:
- гибридный обмен ключами: X25519 + ML-KEM (Kyber/liboqs),
- fail-closed стратегию (нет тихого downgrade без PQC),
- PFS-подобную модель через цепочки ключей (ratchet basis),
- hardening endpoint и конфигурации Android.

## Что реализовано
1. Полный Android Studio/Gradle проект (включая `gradlew`).
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

## Что обязательно доделать до production
- Подключить реальный JNI bridge к `liboqs` (ML-KEM-768/1024).
- Заменить demo-часть X25519 на сетевой pre-key protocol с аутентикацией peer keys.
- Реализовать полноценный Double Ratchet (DH ratchet + skipped keys handling).
- Добавить слой сокрытия метаданных (Tor/I2P/mixnet).
- Внедрить endpoint hardening (attestation, anti-tamper, root detection).
- Провести внешний криптоаудит и pentest.

## Важно
Абсолютно «невзламываемого» мессенджера не существует. Этот проект — серьёзная инженерная база, но не финальный production-продукт без пунктов выше.
