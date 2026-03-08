cmake_minimum_required(VERSION 3.20)

project(vaultc
    VERSION 0.1.0
    DESCRIPTION "VaultC — Personal Password Manager"
    LANGUAGES C
)

# ── Language Standard ──────────────────────────────────────────────────────────
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ── Output Directories ─────────────────────────────────────────────────────────
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ── Platform Detection ─────────────────────────────────────────────────────────
if(WIN32)
    message(STATUS "Platform: Windows")
    add_compile_definitions(VAULTC_PLATFORM_WINDOWS=1)
elseif(APPLE)
    message(STATUS "Platform: macOS")
    add_compile_definitions(VAULTC_PLATFORM_MACOS=1)
elseif(UNIX)
    message(STATUS "Platform: Linux")
    add_compile_definitions(VAULTC_PLATFORM_LINUX=1)
else()
    message(FATAL_ERROR "Unsupported platform")
endif()

# ── Compiler Warnings ──────────────────────────────────────────────────────────
if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

# ── Build Type Defaults ────────────────────────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

# Sanitizers in Debug mode (GCC/Clang only)
if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND NOT MSVC)
    add_compile_options(-fsanitize=address,undefined -g3 -O0)
    add_link_options(-fsanitize=address,undefined)
    message(STATUS "Sanitizers: AddressSanitizer + UBSan enabled")
endif()

# ── Find Dependencies ──────────────────────────────────────────────────────────
find_package(PkgConfig REQUIRED)

# libsodium
pkg_check_modules(SODIUM REQUIRED libsodium)

# SQLite3
find_package(SQLite3 REQUIRED)

# GTK4
pkg_check_modules(GTK4 REQUIRED gtk4)

message(STATUS "libsodium: ${SODIUM_VERSION}")
message(STATUS "SQLite3:   ${SQLite3_VERSION}")
message(STATUS "GTK4:      ${GTK4_VERSION}")

# ── Include Directories ────────────────────────────────────────────────────────
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${SODIUM_INCLUDE_DIRS}
    ${SQLite3_INCLUDE_DIRS}
    ${GTK4_INCLUDE_DIRS}
)

# ── Subdirectories ─────────────────────────────────────────────────────────────
enable_testing()
add_subdirectory(src)
add_subdirectory(tests)

# ── Install ────────────────────────────────────────────────────────────────────
install(TARGETS vaultc DESTINATION bin)

if(UNIX AND NOT APPLE)
    install(FILES packaging/com.vaultc.app.desktop
            DESTINATION share/applications)
    install(FILES packaging/com.vaultc.app.png
            DESTINATION share/icons/hicolor/256x256/apps)
endif()

# ── CPack (packaging) ──────────────────────────────────────────────────────────
set(CPACK_PACKAGE_NAME "VaultC")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY ${PROJECT_DESCRIPTION})
if(WIN32)
    set(CPACK_GENERATOR "NSIS")
elseif(APPLE)
    set(CPACK_GENERATOR "DragNDrop")
else()
    set(CPACK_GENERATOR "DEB;RPM")
endif()
include(CPack)
