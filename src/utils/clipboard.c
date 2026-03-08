/*
 * VaultC — Clipboard Management (set, auto-clear)
 * File: src/utils/clipboard.c
 *
 * Uses gdk_clipboard_set_text() for copy and g_timeout_add_seconds()
 * for auto-clear after a configurable delay.
 */

#include "vaultc/utils.h"

#include <gtk/gtk.h>
#include <string.h>

/* ── Auto-clear state ──────────────────────────────────────────────────────── */

static guint g_clear_timer_id = 0;

/* ── Timeout callback: clear clipboard ─────────────────────────────────────── */

static gboolean on_clipboard_clear_timeout(gpointer user_data)
{
    (void)user_data;

    GdkDisplay *display = gdk_display_get_default();
    if (display != NULL)
    {
        GdkClipboard *clipboard = gdk_display_get_clipboard(display);
        gdk_clipboard_set_text(clipboard, "");
    }

    g_clear_timer_id = 0;
    return G_SOURCE_REMOVE;
}

/* ── Copy text to system clipboard ─────────────────────────────────────────── */

void clipboard_set_text(void *widget, const char *text)
{
    (void)widget;

    if (text == NULL)
    {
        return;
    }

    GdkDisplay *display = gdk_display_get_default();
    if (display == NULL)
    {
        return;
    }

    GdkClipboard *clipboard = gdk_display_get_clipboard(display);
    gdk_clipboard_set_text(clipboard, text);
}

/* ── Schedule clipboard auto-clear ─────────────────────────────────────────── */

void clipboard_schedule_clear(int seconds)
{
    /* Cancel any existing timer */
    if (g_clear_timer_id > 0)
    {
        g_source_remove(g_clear_timer_id);
        g_clear_timer_id = 0;
    }

    if (seconds <= 0)
    {
        return;
    }

    g_clear_timer_id = g_timeout_add_seconds(
        (guint)seconds, on_clipboard_clear_timeout, NULL);
}

/* ── Clear clipboard immediately ───────────────────────────────────────────── */

void clipboard_clear_now(void)
{
    /* Cancel pending timer */
    if (g_clear_timer_id > 0)
    {
        g_source_remove(g_clear_timer_id);
        g_clear_timer_id = 0;
    }

    GdkDisplay *display = gdk_display_get_default();
    if (display != NULL)
    {
        GdkClipboard *clipboard = gdk_display_get_clipboard(display);
        gdk_clipboard_set_text(clipboard, "");
    }
}
