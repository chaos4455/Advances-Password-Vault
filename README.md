# 🛡️ Advanced Password Vault: Secure CLI Architecture (POC/MVP)

This repository presents an elegant and robust Proof-of-Concept (POC) for a local, command-line interface (CLI) driven password vault. The core design philosophy centers on **Maximum Security** through a multi-layered cryptographic architecture where all sensitive data, including service names and credentials, is stored in a **100% encrypted state**.

The system demonstrates advanced techniques in: Key Derivation Functions (KDFs), Authenticated Encryption (AEAD), and secure database design for zero-plaintext storage.

---

## 🚀 Project Status & Technology Stack

| Component | Status | Description |
| :---: | :---: | :--- |
| ![Status](https://img.shields.io/badge/Status-POC%20MVP-blue?style=for-the-badge) | **MVP** | Functional Proof-of-Concept of the core pipeline. |
| ![Language](https://img.shields.io/badge/Language-Python%203.9%2B-blue?style=for-the-badge&logo=python) | **Primary** | Python 3.9+ with `cryptography` library. |
| ![Security](https://img.shields.io/badge/Encryption-AES--256%20GCM%20(AEAD)-green?style=for-the-badge) | **Vault Cryptology** | AES-256 GCM (Galois/Counter Mode) for data and key wrapping. |
| ![KDF](https://img.shields.io/badge/KDF-PBKDF2HMAC%20(1M%20Iter)-green?style=for-the-badge) | **Key Derivation** | PBKDF2HMAC with SHA-256 and 1,000,000 iterations. |
| ![Database](https://img.shields.io/badge/Storage-SQLite%20(Full%20Enc)-blue?style=for-the-badge&logo=sqlite) | **Local Persistence** | SQLite3, storing only binary cryptographic blobs (`BLOB`). |
| ![UI](https://img.shields.io/badge/Interface-Rich%20CLI-blue?style=for-the-badge&logo=terminal) | **User Experience** | `rich` library for a professional, highly readable console interface. |

---

## 🔑 Architectural Overview: The Master Key Flow

The system operates on a Zero-Trust principle, ensuring that the Master Key used for data encryption is never exposed in a recoverable format without the correct **Master Password**.

### 1. User Authentication & Key Derivation (KDF)

This stage is the system's primary defense against brute-force attacks:

| Component | Function | Security Feature |
| :--- | :--- | :--- |
| **Master Password** | User input, never stored. | High entropy source for the vault access. |
| **Salt** | Unique, randomly generated 16-byte value. | Ensures two identical passwords yield two different Key Encryption Keys (KEKs). Stored in `masterkey.storagekey`. |
| **PBKDF2-HMAC** | Key Derivation Function. | Uses **1,000,000 iterations** with **SHA-256** to deliberately slow down the verification process, rendering online and offline brute-force attacks computationally infeasible. |
| **Key Encryption Key (KEK)** | The output key from the KDF process. | Used *only* to encrypt and decrypt the Master Key. |

### 2. Master Key Wrapping (Key Storage)

The actual key used to encrypt the entire vault, the **Master Key (AES-256)**, is stored securely using the KEK derived in the previous step:

*   The **Master Key** is generated as a random 32-byte (AES-256) key upon first setup.
*   This Master Key is encrypted using the **KEK** and the **AES-GCM (Authenticated Encryption)** algorithm.
*   The resulting ciphertext, along with its unique **Nonce** and **Salt**, is stored in the JSON file `masterkey.storagekey`.
*   **Result:** The Master Key is always at rest as an encrypted blob, and its integrity is verified via the AES-GCM tag check during every login attempt (`InvalidTag` is the trigger for "Incorrect Password").

---

## 💾 Vault Data Storage Architecture: Full Encryption

The central component, the **Crypto Vault DB** (`sqlite3`), adheres to a "Full Data Encryption" model. The SQL database stores **no plaintext information** that could compromise an entry if the file system were breached.

### Data Schema (`passwords` table)

| Field | Storage Type | Encryption State | Rationale |
| :--- | :--- | :--- | :--- |
| `id` | `INTEGER PRIMARY KEY` | Unencrypted | Necessary for atomic SQL operations (Update, Delete) and CLI indexing. |
| `service_nonce` | `BLOB` | Nonce | Unique IV for the Service Name ciphertext. |
| `service_ciphertext` | `BLOB` | **AES-256 GCM** | The *Service Name* is encrypted, preventing easy enumeration of services in the database file. |
| `data_nonce` | `BLOB` | Nonce | Unique IV for the Credentials ciphertext. |
| `data_ciphertext` | `BLOB` | **AES-256 GCM** | Encrypted `{'email':..., 'password':...}` JSON object. |

### Full Encryption Model

1.  **Authenticated Encryption:** All vault data is encrypted using **AES-256 in Galois/Counter Mode (GCM)**. GCM provides **confidentiality** (encryption) and **integrity/authenticity** (tamper-proofing via a cryptographic tag). If an attacker alters a single byte in the database, the decryption process will fail with an `InvalidTag` exception.
2.  **Separate Encryption:** The *Service Name* is encrypted separately from the *Email/Password* data. This separation allows for potentially different access policies in future versions, but currently ensures a slightly higher level of operational security.
3.  **In-Memory Processing:** Due to the 100% encryption, the SQL database cannot perform functions like `ORDER BY` or `LIKE '%search%'`. The system mitigates this by fetching all entries, decrypting them in **RAM**, and then performing sorting (by service name) and filtering within the secure application logic.

---

## 💻 Rich Command Line Interface (CLI)

The user experience is handled by the `rich` library, providing a high-fidelity console experience suitable for enterprise tools.

### Operational Features (CRUD)

| Command | Description | Implementation Detail |
| :--- | :--- | :--- |
| **👁️ View Passwords** | Lists all vault entries (ID, Service, Email). Password field is masked (`******`) unless explicitly selected for viewing/editing. | Uses `rich.Table` for clean, colorized display. Sorting is done post-decryption in Python/RAM. |
| **➕ New Senha** | Adds a new entry (Service, Email, Password). | Securely encrypts and commits two separate `AES-GCM` blobs to the database. |
| **✏️ Editar** | Allows modification of an existing entry. | Fetches the existing entry, decrypts it, and uses `rich.prompt` with current values as defaults for seamless editing. A successful update results in a full **re-encryption** of the record. |
| **🗑️ Deletar** | Permanently removes an entry from the database. | Requires a confirmation prompt to prevent accidental data loss. |
| **🚪 Sair** | Gracefully closes the program. | Ensures the secure SQLite connection is closed (`conn.close()`) before exiting. |

### Resilience

*   **Anti-Brute Force Delay:** After an unsuccessful Master Password attempt, the system enforces a `time.sleep(2)` second delay, significantly frustrating any repeated, automated login attempts.
*   **Decryption Error Handling:** Built-in `try/except InvalidTag` blocks handle scenarios where data might be corrupt or tampered with, alerting the user without crashing the application.

---

## 🛠️ Usage

### Prerequisites

```bash
# Assuming Python 3.9+ and pip are installed
pip install cryptography rich inquirer
