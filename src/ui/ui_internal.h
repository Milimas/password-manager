/*
 * VaultC — UI Internal Headers
 * File: src/ui/ui_internal.h
 *
 * Shared declarations for all UI modules. Not part of the public API.
 */

#ifndef VAULTC_UI_INTERNAL_H
#define VAULTC_UI_INTERNAL_H

#include <gtk/gtk.h>

/* ── ui_app.c ──────────────────────────────────────────────────────────────── */

/**
 * Show the unlock dialog (vault exists).
 */
void ui_show_unlock_dialog(GtkApplication *app);

/**
 * Show the welcome/create dialog (no vault yet).
 */
void ui_show_welcome_dialog(GtkApplication *app);

/* ── ui_main_window.c ──────────────────────────────────────────────────────── */

/**
 * Create and show the main password list window.
 */
void ui_show_main_window(GtkApplication *app);

/* ── ui_unlock_dialog.c ────────────────────────────────────────────────────── */

/* (declared above as ui_show_unlock_dialog) */

/* ── ui_entry_dialog.c ─────────────────────────────────────────────────────── */

/**
 * Show the add/edit entry dialog.
 * @param parent  Parent window.
 * @param uuid    NULL for new entry, UUID string for editing.
 */
void ui_show_entry_dialog(GtkWindow *parent, const char *uuid);

/* ── ui_import_dialog.c ────────────────────────────────────────────────────── */

/**
 * Show the CSV import dialog.
 */
void ui_show_import_dialog(GtkWindow *parent);

/* ── ui_generator_dialog.c ─────────────────────────────────────────────────── */

/**
 * Show the password generator dialog.
 * @param parent   Parent window.
 * @param target   Optional GtkEditable to paste result into (nullable).
 */
void ui_show_generator_dialog(GtkWindow *parent, GtkEditable *target);

/* ── ui_settings_dialog.c ──────────────────────────────────────────────────── */

/**
 * Show the settings dialog.
 */
void ui_show_settings_dialog(GtkWindow *parent);

#endif /* VAULTC_UI_INTERNAL_H */
