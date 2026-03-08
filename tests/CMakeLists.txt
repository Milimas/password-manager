# ── VaultC Tests ───────────────────────────────────────────────────────────────

enable_testing()

# ── Test helper: adds a test executable linked against vaultc_core ─────────────
function(vaultc_add_test name source)
    add_executable(${name} ${source})
    target_include_directories(${name} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/tests
        ${SODIUM_INCLUDE_DIRS}
        ${SQLite3_INCLUDE_DIRS}
    )
    target_link_libraries(${name}
        vaultc_core
        ${SODIUM_LIBRARIES}
        SQLite::SQLite3
    )
    target_link_directories(${name} PRIVATE
        ${SODIUM_LIBRARY_DIRS}
    )
    add_test(NAME ${name} COMMAND ${name})
endfunction()

# ── Test targets ───────────────────────────────────────────────────────────────
vaultc_add_test(test_crypto test_crypto.c)
vaultc_add_test(test_vault  test_vault.c)
vaultc_add_test(test_db     test_db.c)
vaultc_add_test(test_import test_import.c)
vaultc_add_test(test_pwgen  test_pwgen.c)

# ── Pass fixtures directory path to test_import ────────────────────────────────
target_compile_definitions(test_import PRIVATE
    FIXTURES_DIR="${CMAKE_SOURCE_DIR}/tests/fixtures"
)
