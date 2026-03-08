# VaultC — UML Diagrams

All diagrams use Mermaid syntax and can be rendered at https://mermaid.live

---

## 1. Module Dependency Diagram (Component View)

```mermaid
graph TD
    UI["UI Layer<br/>(GTK4)<br/>src/ui/"]
    APP["Application Layer<br/>src/app/session.c"]
    VAULT["vault.c<br/>Vault I/O"]
    DB["db.c<br/>SQLite CRUD"]
    CRYPTO["crypto.c<br/>libsodium"]
    IMPORT["import/<br/>CSV Importers"]
    PWGEN["generator/<br/>pwgen.c"]
    UTILS["utils/<br/>clipboard, totp, uuid"]

    UI --> APP
    APP --> VAULT
    APP --> IMPORT
    APP --> PWGEN
    APP --> UTILS
    VAULT --> CRYPTO
    VAULT --> DB
    DB --> CRYPTO
    IMPORT --> DB

    CRYPTO -.->|libsodium| EXT1[("libsodium")]
    DB -.->|SQLite3| EXT2[("sqlite3")]
    UI -.->|GTK4| EXT3[("GTK4 / GLib")]
```

---

## 2. Class Diagram (Core Data Structures)

```mermaid
classDiagram
    class VaultHandle {
        -sqlite3* db
        -uint8_t key[32]
        -uint8_t salt[32]
        -char* path
        -uint32_t kdf_ops
        -uint32_t kdf_mem
        -int is_modified
        +vault_open(path, password) VaultHandle*
        +vault_save() VaultcError
        +vault_close() void
        +vault_change_password(old, new) VaultcError
        +vault_create(path, password) VaultHandle*
    }

    class Entry {
        +char uuid[37]
        +char* title
        +char* url
        +char* username
        +char* password
        +char* notes
        +char* totp_secret
        +char* category
        +int is_favorite
        +int64_t created_at
        +int64_t updated_at
        +int64_t last_used
        +char* source
    }

    class EntryList {
        +Entry** items
        +size_t count
        +size_t capacity
    }

    class ImportResult {
        +int imported
        +int skipped_duplicates
        +int errors
        +char** error_messages
        +ImportFormat format_detected
    }

    class PwgenOptions {
        +int length
        +int use_uppercase
        +int use_lowercase
        +int use_digits
        +int use_symbols
        +char* exclude_chars
        +int min_uppercase
        +int min_digits
        +int min_symbols
    }

    class CryptoContext {
        +uint8_t key[32]
        +uint8_t nonce[16]
        +uint8_t salt[32]
        +uint32_t ops_limit
        +uint32_t mem_limit
    }

    class VaultHeader {
        +uint32_t magic
        +uint32_t version
        +uint32_t flags
        +uint8_t salt[32]
        +uint8_t nonce[16]
        +uint32_t kdf_mem
        +uint32_t kdf_ops
        +uint64_t ciphertext_len
        +uint8_t tag[16]
    }

    VaultHandle "1" --> "1" EntryList : contains
    EntryList "1" --> "*" Entry : holds
    VaultHandle "1" --> "1" VaultHeader : reads/writes
    VaultHandle "1" --> "1" CryptoContext : uses
```

---

## 3. Sequence Diagram — Vault Unlock Flow

```mermaid
sequenceDiagram
    actor User
    participant UnlockDlg as UnlockDialog (GTK4)
    participant Session as session.c
    participant Vault as vault.c
    participant Crypto as crypto.c
    participant DB as db.c

    User->>UnlockDlg: Enter master password + click Unlock
    UnlockDlg->>Session: session_unlock(path, password)
    Session->>Vault: vault_open(path, password)

    Vault->>Vault: Read vault file header
    Vault->>Vault: Validate magic number & version
    Vault->>Crypto: crypto_derive_key(password, salt, ops, mem)
    Crypto->>Crypto: Argon2id KDF (intentionally slow)
    Crypto-->>Vault: 32-byte derived key

    Vault->>Crypto: crypto_decrypt(ciphertext, key, nonce, tag)
    alt Authentication tag valid
        Crypto-->>Vault: Decrypted SQLite bytes
        Vault->>DB: sqlite3_open_v2(":memory:")
        DB->>DB: Load decrypted bytes into memory DB
        DB-->>Vault: sqlite3* handle
        Vault-->>Session: VaultHandle* (success)
        Session-->>UnlockDlg: SESSION_OK
        UnlockDlg->>UnlockDlg: Close dialog
        UnlockDlg->>UnlockDlg: Open MainWindow
    else Authentication tag invalid
        Crypto-->>Vault: VAULTC_ERR_BAD_PASSWORD
        Vault-->>Session: NULL
        Session-->>UnlockDlg: SESSION_ERR_BAD_PASSWORD
        UnlockDlg->>User: Show "Incorrect password" error
    end
```

---

## 4. Sequence Diagram — Save Entry Flow

```mermaid
sequenceDiagram
    actor User
    participant EntryDlg as EntryDialog (GTK4)
    participant Session as session.c
    participant DB as db.c
    participant Vault as vault.c
    participant Crypto as crypto.c
    participant FS as Filesystem

    User->>EntryDlg: Fill form + click Save
    EntryDlg->>EntryDlg: Validate required fields
    EntryDlg->>Session: session_save_entry(Entry*)

    Session->>DB: db_entry_create(db, entry) or db_entry_update()
    DB->>DB: INSERT or UPDATE in memory SQLite
    DB-->>Session: VAULTC_OK

    Session->>Vault: vault_save(handle)
    Vault->>DB: sqlite3_serialize(db) → raw bytes
    Vault->>Crypto: crypto_random_bytes(nonce, 16)
    Vault->>Crypto: crypto_encrypt(raw_bytes, key, nonce)
    Crypto-->>Vault: ciphertext + GCM tag

    Vault->>FS: Write to vault.vcf.tmp (atomic)
    FS-->>Vault: write OK
    Vault->>FS: rename(vault.vcf.tmp → vault.vcf)
    FS-->>Vault: rename OK

    Vault-->>Session: VAULTC_OK
    Session-->>EntryDlg: success
    EntryDlg->>EntryDlg: Close dialog, refresh list
```

---

## 5. Sequence Diagram — CSV Import Flow

```mermaid
sequenceDiagram
    actor User
    participant ImportDlg as ImportDialog (GTK4)
    participant Importer as importer.c
    participant Parser as csv_parser.c
    participant DB as db.c
    participant Session as session.c

    User->>ImportDlg: Select CSV file + click Import
    ImportDlg->>Importer: import_detect_format(csv_path)
    Importer->>Parser: csv_read_header(path)
    Parser-->>Importer: column names[]
    Importer->>Importer: Match columns → known format signatures
    Importer-->>ImportDlg: ImportFormat (GOOGLE / FIREFOX / IOS / UNKNOWN)

    alt Known format
        ImportDlg->>ImportDlg: Show preview table (first 5 rows)
        User->>ImportDlg: Confirm import
        ImportDlg->>Importer: import_google_csv(db, path, opts)
        loop For each CSV row
            Importer->>Parser: csv_read_row()
            Parser-->>Importer: field values[]
            Importer->>Importer: Map fields → Entry struct
            Importer->>DB: db_entry_create() or check duplicate
            DB-->>Importer: OK or DUPLICATE
        end
        Importer-->>ImportDlg: ImportResult{imported, skipped, errors}
        ImportDlg->>Session: session_vault_save()
        ImportDlg->>User: Show summary dialog
    else Unknown format
        ImportDlg->>User: Show field-mapping UI
        User->>ImportDlg: Map columns manually
        ImportDlg->>Importer: import_generic_csv(db, path, field_map)
    end
```

---

## 6. State Machine — Application Session State

```mermaid
stateDiagram-v2
    [*] --> NoVault : App launch, no vault file found

    NoVault --> Locked : vault_create() succeeds
    NoVault --> Locked : vault_open() — existing file selected

    Locked --> Unlocked : Correct master password
    Locked --> Locked : Wrong master password (show error)

    Unlocked --> Editing : User opens entry dialog
    Unlocked --> Importing : User opens import dialog
    Unlocked --> Generating : User opens generator

    Editing --> Unlocked : Save or Cancel
    Importing --> Unlocked : Import complete or Cancel
    Generating --> Unlocked : Close generator

    Unlocked --> Locked : User clicks Lock
    Unlocked --> Locked : Auto-lock timeout fires
    Unlocked --> Locked : Window loses focus (if setting enabled)

    Unlocked --> [*] : Vault saved → App quit
    Locked --> [*] : App quit (no save needed)
```

---

## 7. File Structure Tree

```mermaid
graph LR
    ROOT["vaultc/"]
    ROOT --> SRC["src/"]
    ROOT --> INC["include/vaultc/"]
    ROOT --> TST["tests/"]
    ROOT --> DOC["docs/"]
    ROOT --> CMAKE["CMakeLists.txt"]
    ROOT --> README["README.md"]

    SRC --> CORE["core/"]
    SRC --> UI_DIR["ui/"]
    SRC --> IMP["import/"]
    SRC --> GEN["generator/"]
    SRC --> UTL["utils/"]
    SRC --> MAIN["main.c"]

    CORE --> CRYPTO_C["crypto.c"]
    CORE --> VAULT_C["vault.c"]
    CORE --> DB_C["db.c"]

    UI_DIR --> APP_C["ui_app.c"]
    UI_DIR --> MAIN_WIN["ui_main_window.c"]
    UI_DIR --> UNLOCK["ui_unlock_dialog.c"]
    UI_DIR --> ENTRY_DLG["ui_entry_dialog.c"]
    UI_DIR --> IMPORT_DLG["ui_import_dialog.c"]
    UI_DIR --> GEN_DLG["ui_generator_dialog.c"]
    UI_DIR --> SET_DLG["ui_settings_dialog.c"]

    IMP --> DETECT["importer.c"]
    IMP --> GOOGLE["import_google.c"]
    IMP --> FIREFOX["import_firefox.c"]
    IMP --> IOS["import_ios.c"]
    IMP --> BWARDEN["import_bitwarden.c"]
    IMP --> GENERIC["import_generic.c"]

    GEN --> PWGEN_C["pwgen.c"]
    UTL --> CLIP["clipboard.c"]
    UTL --> UUID_C["uuid.c"]
    UTL --> TOTP_C["totp.c"]
    UTL --> CSV_C["csv_parser.c"]

    INC --> TYPES_H["types.h"]
    INC --> VAULT_H["vault.h"]
    INC --> CRYPTO_H["crypto.h"]
    INC --> DB_H["db.h"]
    INC --> IMPORT_H["importer.h"]
    INC --> PWGEN_H["pwgen.h"]

    TST --> TEST_CRYPTO["test_crypto.c"]
    TST --> TEST_VAULT["test_vault.c"]
    TST --> TEST_DB["test_db.c"]
    TST --> TEST_IMPORT["test_import.c"]
    TST --> TEST_PWGEN["test_pwgen.c"]
    TST --> HARNESS["harness.h"]

    DOC --> ARCH["ARCHITECTURE.md"]
    DOC --> CODING["CODING_STANDARDS.md"]
    DOC --> UML_DIR["UML/"]
    DOC --> AGENT["AGENT_GUIDE.md"]
    DOC --> VSPEC["VAULT_FORMAT_SPEC.md"]
```
