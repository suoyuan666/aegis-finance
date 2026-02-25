# aegis-finance

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Rust](https://img.shields.io/badge/built_with-Rust-dca282.svg)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/status-active_development-green.svg)]()

**aegis-finance** is a cross-platform, privacy-first, and absolutely secure core logic library for personal finance management.

This crate serves as the **headless engine** for a bookkeeping application. It handles data modeling, local encrypted storage, and business logic. It is designed to be decoupled from the UI, making it suitable for integration with ative desktop apps or CLI tools.

## 🛡️ Security Architecture

Security and privacy are the foundational pillars of `aegis-finance`. We do not rely on "security through obscurity." Instead, we employ industry-standard cryptographic primitives to ensure your financial data remains yours alone.

### 1. Data at Rest Encryption (SQLCipher)
The local database is not a standard SQLite file. We utilize **SQLCipher** (via `rusqlite` with bundled build) to perform full-database encryption with 256-bit AES. If the device is lost or the file is stolen, the data is mathematically inaccessible without the key.

### 2. Robust Key Derivation (Argon2id)
We do not trust simple passwords.
*   **Algorithm:** We use the **Argon2id** algorithm (via the `argon2` crate), the winner of the Password Hashing Competition, to derive the encryption key from the user's master password.
*   **Configuration:** Configured to be memory-hard and CPU-intensive to resist brute-force and rainbow table attacks.
*   **Encoding:** The derived key is encoded using the `hex` crate before being passed to the database engine.

### 3. Memory Hygiene (Zeroize)
We take memory safety seriously.
*   **Zero-Knowledge Handling:** The master password and derived keys are treated as sensitive secrets.
*   **Immediate Cleanup:** Utilizing the `zeroize` crate, sensitive memory regions (containing passwords or keys) are overwritten with zeros immediately after the database connection is established. This prevents secrets from lingering in RAM or leaking into swap/core dumps.

## 🧩 Modules & Status

| Module | Description | Status |
| :--- | :--- | :--- |
| **Models** | Core data structures (Transactions, Accounts, etc.) with serialization support. | ✅ **Completed** |
| **Database** | SQLite wrapper with SQLCipher encryption and CRUD operations. | ✅ **Completed** |
| **Crypto** | Argon2id key derivation and Zeroize memory management logic. | ✅ **Completed** |
| **API** | Facade layer exposed to external consumers. | 🚧 **In Progress** |
| **Sync** | E2EE Cloud Synchronization (WebDAV/Git repository). | ⏳ **Planned / WIP** |

> **Current Focus:** We are currently implementing the **WebDAV** synchronization logic. The goal is to support encrypted data sync across platforms without relying on proprietary cloud services.

## 🤝 Contributing

This project is built by a system developer for those who care deeply about privacy.
*   Issues and Pull Requests are welcome.
*   Please ensure `cargo test` passes before submitting.

## 📄 License

This project is licensed under the **GNU General Public License v3.0 (GPLv3)**.
See the [LICENSE](LICENSE) file for details.
