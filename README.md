# VaultC — Planning & Implementation Package

A personal password manager written in C, with GTK4 GUI, cross-platform support
(Windows, Linux, macOS), libsodium encryption, and multi-platform CSV import.

---

## What's In This Package

```
vaultc-planning/
├── docs/
│   ├── ARCHITECTURE.md        ← System design, layers, data flow, threat model
│   ├── CODING_STANDARDS.md    ← C style guide, memory safety, error handling
│   ├── AGENT_GUIDE.md         ← Step-by-step implementation plan for AI agents
│   ├── VAULT_FORMAT_SPEC.md   ← Binary vault file format (byte-level spec)
│   └── UML/
│       └── DIAGRAMS.md        ← All UML diagrams in Mermaid syntax
│
└── scaffold/
    ├── CMakeLists.txt          ← Cross-platform CMake build file
    ├── include/vaultc/
    │   └── types.h             ← All shared type definitions
    └── tests/
        └── harness.h           ← Zero-dependency test harness
```

---

## Tech Stack

| Component       | Choice         | Reason                                          |
|-----------------|----------------|-------------------------------------------------|
| Language        | C11            | Security, control, cross-platform ABI           |
| GUI             | GTK4           | Native look, cross-platform, C-native           |
| Cryptography    | libsodium      | Gold standard, easy API, Argon2id + AES-GCM     |
| Database        | SQLite3        | Embedded, structured, serializable              |
| Vault format    | Custom binary  | SQLite3 inside AES-256-GCM encrypted container  |
| Build system    | CMake 3.20+    | Best cross-platform C build support             |

---

## Implementation Order

Follow `docs/AGENT_GUIDE.md` which breaks work into 8 phases:

| Phase | Description                        | Key Output                    |
|-------|------------------------------------|-------------------------------|
| 0     | Project scaffold                   | CMake build, empty files      |
| 1     | Crypto layer                       | crypto.c + tests              |
| 2     | Vault file I/O                     | vault.c + tests               |
| 3     | SQLite CRUD                        | db.c + tests                  |
| 4     | Utilities (UUID, CSV, TOTP, clip)  | utils/ + tests                |
| 5     | Import engine                      | import/ + tests + fixtures    |
| 6     | Password generator                 | pwgen.c + tests               |
| 7     | GTK4 UI                            | All ui_*.c files              |
| 8     | Integration & polish               | Full app working              |

---

## Quick Start (Linux)

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt install build-essential cmake pkg-config \
    libsodium-dev libsqlite3-dev libgtk-4-dev

# Configure
cmake -B build -DCMAKE_BUILD_TYPE=Debug

# Build
cmake --build build

# Test
ctest --test-dir build --output-on-failure

# Run
./build/bin/vaultc
```

## Quick Start (macOS)

```bash
brew install cmake libsodium sqlite gtk4
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

## Quick Start (Windows — MSYS2)

```bash
pacman -S mingw-w64-x86_64-cmake mingw-w64-x86_64-libsodium \
          mingw-w64-x86_64-sqlite3 mingw-w64-x86_64-gtk4
cmake -B build -G "MinGW Makefiles"
cmake --build build
```

---

## Security Decisions (Quick Reference)

- **Argon2id** KDF: deliberately slow to defeat offline brute-force attacks
- **AES-256-GCM**: authenticated encryption — detects any tampering
- **Fresh nonce every save**: prevents nonce-reuse attacks
- **sodium_memzero**: prevents compiler from optimizing away key erasure
- **Atomic writes**: temp file + rename prevents half-written vaults
- **In-memory SQLite**: plaintext database never touches disk

---

## Supported Import Sources

| Platform         | Format  | How to Export                              |
|------------------|---------|---------------------------------------------|
| Google Passwords | CSV     | passwords.google.com → Settings → Export   |
| Firefox          | CSV     | about:logins → ⋯ menu → Export Passwords   |
| iOS/iCloud       | CSV     | Settings → Passwords → ⋯ → Export         |
| Bitwarden        | CSV     | Web vault → Tools → Export → .csv         |
| LastPass         | CSV     | Account Options → Advanced → Export        |

---

## Diagrams

Render the Mermaid diagrams in `docs/UML/DIAGRAMS.md` at:
- https://mermaid.live (paste diagram source)
- VS Code: install "Markdown Preview Mermaid Support" extension
- GitHub: renders Mermaid natively in markdown files
