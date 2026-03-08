# ── VaultC Source Build ─────────────────────────────────────────────────────────

# ── Core library (no GTK dependency) ──────────────────────────────────────────
set(VAULTC_CORE_SOURCES
    core/errors.c
    core/crypto.c
    core/vault.c
    core/db.c
    import/importer.c
    import/import_google.c
    import/import_firefox.c
    import/import_ios.c
    import/import_bitwarden.c
    import/import_generic.c
    generator/pwgen.c
    utils/clipboard.c
    utils/uuid.c
    utils/totp.c
    utils/csv_parser.c
    app/session.c
)

add_library(vaultc_core STATIC ${VAULTC_CORE_SOURCES})

target_include_directories(vaultc_core PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${SODIUM_INCLUDE_DIRS}
    ${SQLite3_INCLUDE_DIRS}
    ${GTK4_INCLUDE_DIRS}
)

target_link_libraries(vaultc_core
    ${SODIUM_LIBRARIES}
    SQLite::SQLite3
    ${GTK4_LIBRARIES}
)

target_link_directories(vaultc_core PUBLIC
    ${SODIUM_LIBRARY_DIRS}
    ${GTK4_LIBRARY_DIRS}
)

# ── UI sources + executable ────────────────────────────────────────────────────
set(VAULTC_UI_SOURCES
    ui/ui_app.c
    ui/ui_main_window.c
    ui/ui_unlock_dialog.c
    ui/ui_entry_dialog.c
    ui/ui_import_dialog.c
    ui/ui_generator_dialog.c
    ui/ui_settings_dialog.c
    main.c
)

add_executable(vaultc ${VAULTC_UI_SOURCES})

target_link_libraries(vaultc
    vaultc_core
    ${GTK4_LIBRARIES}
)

target_link_directories(vaultc PUBLIC
    ${GTK4_LIBRARY_DIRS}
)
