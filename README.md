# Quantum Messenger (Android Studio template)

Этот шаблон создаёт основу Android-проекта для приватного мессенджера с упором на:
- гибридный обмен ключами: X25519 + ML-KEM (Kyber),
- fail-closed подход (без тихого отката на слабую криптографию),
- частую ротацию ключей (база для PFS/Double Ratchet),
- защиту конечной точки (FLAG_SECURE, запрет backup/cleartext).

## Что уже реализовано
1. Минимальный Android Studio проект (`:app`) на Kotlin.
2. `HybridSessionManager`: объединяет секреты от классического и постквантового KEM.
3. `LiboqsMlKemProvider`: интерфейс для JNI-моста к `liboqs` (бесплатно, без спецоборудования).
4. Базовые hardening-настройки манифеста и release-сборки.

## Что нужно сделать обязательно перед продом
- Подключить реальный JNI bridge к `liboqs` и ML-KEM-768/1024.
- Реализовать полноценный X25519 ECDH (не заглушку).
- Добавить Double Ratchet на сообщение (PFS на уровне каждого сообщения).
- Скрывать метаданные через Tor/I2P/mixnet relay слой.
- Защитить endpoint: root/jailbreak detection, anti-tamper, secure enclave where possible.
- Провести криптоаудит и pentest.

## Важно
Ни один мессенджер нельзя честно назвать «невзламываемым». Этот проект — безопасный стартовый каркас с правильным направлением (PQC + metadata resistance + PFS).
