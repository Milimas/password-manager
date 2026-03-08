/*
 * VaultC — Clipboard Management (set, auto-clear)
 * File: src/utils/clipboard.c
 *
 * Stubbed implementation — GTK4 wiring will be added in Phase 7.
 */

#include "vaultc/utils.h"

/* ── Stub: copy text to system clipboard ───────────────────────────────────── */

void clipboard_set_text(void *widget, const char *text)
{
    /* TODO Phase 7: gdk_clipboard_set_text() */
    (void)widget;
    (void)text;
}

/* ── Stub: schedule clipboard auto-clear ───────────────────────────────────── */

void clipboard_schedule_clear(int seconds)
{
    /* TODO Phase 7: g_timeout_add_seconds() */
    (void)seconds;
}

/* ── Stub: clear clipboard immediately ─────────────────────────────────────── */

void clipboard_clear_now(void)
{
    /* TODO Phase 7: gdk_clipboard_set_text(widget, "") */
}
