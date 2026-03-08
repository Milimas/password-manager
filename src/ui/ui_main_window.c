/*
 * VaultC — Main Window (entry list, search, toolbar)
 * File: src/ui/ui_main_window.c
 *
 * Two-pane layout: left sidebar with search + entry list,
 * right pane with entry detail view.
 */

#include "ui_internal.h"

#include "vaultc/session.h"
#include "vaultc/db.h"
#include "vaultc/utils.h"
#include "vaultc/crypto.h"

#include <string.h>

/* ── Auto-lock timeout (seconds) ───────────────────────────────────────────── */

#define DEFAULT_AUTOLOCK_SECONDS 300

/* ── Main window state ─────────────────────────────────────────────────────── */

typedef struct
{
    GtkApplication *app;
    GtkWindow *window;
    GtkWidget *search_entry;
    GtkWidget *list_box;
    GtkWidget *detail_box;

    /* Detail pane widgets */
    GtkWidget *detail_title;
    GtkWidget *detail_url;
    GtkWidget *detail_username;
    GtkWidget *detail_password;
    GtkWidget *detail_notes;
    GtkWidget *detail_category;
    GtkWidget *detail_totp;
    GtkWidget *detail_totp_row;

    EntryList *entries;
    char *selected_uuid;
    guint autolock_id;
} MainWindow;

/* ── Forward declarations ──────────────────────────────────────────────────── */

static void mw_refresh_list(MainWindow *mw);
static void mw_show_detail(MainWindow *mw, const char *uuid);
static void mw_clear_detail(MainWindow *mw);

/* ── Clipboard: copy password ──────────────────────────────────────────────── */

static void on_copy_password_clicked(GtkButton *btn, gpointer user_data)
{
    const char *uuid = (const char *)user_data;
    (void)btn;

    void *db = session_get_db();
    if (db == NULL)
    {
        return;
    }

    Entry *entry = db_entry_read(db, uuid);
    if (entry == NULL || entry->password == NULL)
    {
        db_free_entry(entry);
        return;
    }

    GdkDisplay *display = gdk_display_get_default();
    GdkClipboard *clipboard = gdk_display_get_clipboard(display);
    gdk_clipboard_set_text(clipboard, entry->password);

    /* Schedule auto-clear after 30 seconds */
    clipboard_schedule_clear(30);

    db_free_entry(entry);
}

/* ── Entry list row creation ───────────────────────────────────────────────── */

static GtkWidget *create_entry_row(const Entry *entry)
{
    GtkWidget *row_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_margin_top(row_box, 4);
    gtk_widget_set_margin_bottom(row_box, 4);
    gtk_widget_set_margin_start(row_box, 8);
    gtk_widget_set_margin_end(row_box, 8);

    /* Icon placeholder */
    GtkWidget *icon = gtk_image_new_from_icon_name("dialog-password");
    gtk_box_append(GTK_BOX(row_box), icon);

    /* Title + username column */
    GtkWidget *text_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_widget_set_hexpand(text_box, TRUE);

    GtkWidget *title_label = gtk_label_new(
        entry->title ? entry->title : "(untitled)");
    gtk_label_set_xalign(GTK_LABEL(title_label), 0.0f);
    gtk_widget_add_css_class(title_label, "heading");
    gtk_box_append(GTK_BOX(text_box), title_label);

    GtkWidget *user_label = gtk_label_new(
        entry->username ? entry->username : "");
    gtk_label_set_xalign(GTK_LABEL(user_label), 0.0f);
    gtk_widget_add_css_class(user_label, "dim-label");
    gtk_box_append(GTK_BOX(text_box), user_label);

    gtk_box_append(GTK_BOX(row_box), text_box);

    /* Copy password button */
    GtkWidget *copy_btn = gtk_button_new_from_icon_name("edit-copy");
    gtk_widget_set_tooltip_text(copy_btn, "Copy Password");
    gtk_widget_set_valign(copy_btn, GTK_ALIGN_CENTER);
    /* Store uuid in button — g_strdup so it outlives the entry */
    char *uuid_copy = g_strdup(entry->uuid);
    g_signal_connect(copy_btn, "clicked",
                     G_CALLBACK(on_copy_password_clicked), uuid_copy);
    g_signal_connect_swapped(copy_btn, "destroy",
                             G_CALLBACK(g_free), uuid_copy);
    gtk_box_append(GTK_BOX(row_box), copy_btn);

    return row_box;
}

/* ── List box row selected ─────────────────────────────────────────────────── */

static void on_row_selected(GtkListBox *list_box, GtkListBoxRow *row,
                            gpointer user_data)
{
    MainWindow *mw = user_data;
    (void)list_box;

    if (row == NULL)
    {
        mw_clear_detail(mw);
        return;
    }

    int idx = gtk_list_box_row_get_index(row);
    if (mw->entries == NULL || idx < 0 || (size_t)idx >= mw->entries->count)
    {
        return;
    }

    const char *uuid = mw->entries->items[idx]->uuid;
    mw_show_detail(mw, uuid);
}

/* ── Search changed ────────────────────────────────────────────────────────── */

static void on_search_changed(GtkSearchEntry *search_entry,
                              gpointer user_data)
{
    MainWindow *mw = user_data;
    (void)search_entry;
    mw_refresh_list(mw);
}

/* ── Toolbar actions ───────────────────────────────────────────────────────── */

static void on_lock_button_clicked(GtkButton *btn, gpointer user_data)
{
    MainWindow *mw = user_data;
    (void)btn;

    session_lock();

    GtkApplication *app = mw->app;
    gtk_window_destroy(mw->window);
    ui_show_unlock_dialog(app);
}

static void on_add_button_clicked(GtkButton *btn, gpointer user_data)
{
    MainWindow *mw = user_data;
    (void)btn;
    ui_show_entry_dialog(mw->window, NULL);
}

static void on_import_button_clicked(GtkButton *btn, gpointer user_data)
{
    MainWindow *mw = user_data;
    (void)btn;
    ui_show_import_dialog(mw->window);
}

static void on_settings_button_clicked(GtkButton *btn, gpointer user_data)
{
    MainWindow *mw = user_data;
    (void)btn;
    ui_show_settings_dialog(mw->window);
}

/* ── Edit entry (double click) ─────────────────────────────────────────────── */

static void on_row_activated(GtkListBox *list_box, GtkListBoxRow *row,
                             gpointer user_data)
{
    MainWindow *mw = user_data;
    (void)list_box;

    int idx = gtk_list_box_row_get_index(row);
    if (mw->entries == NULL || idx < 0 || (size_t)idx >= mw->entries->count)
    {
        return;
    }

    const char *uuid = mw->entries->items[idx]->uuid;
    ui_show_entry_dialog(mw->window, uuid);
}

/* ── Auto-lock timeout ─────────────────────────────────────────────────────── */

static gboolean on_autolock_timeout(gpointer user_data)
{
    MainWindow *mw = user_data;
    on_lock_button_clicked(NULL, mw);
    mw->autolock_id = 0;
    return G_SOURCE_REMOVE;
}

/* ── Detail pane ───────────────────────────────────────────────────────────── */

static void mw_clear_detail(MainWindow *mw)
{
    g_free(mw->selected_uuid);
    mw->selected_uuid = NULL;

    gtk_label_set_text(GTK_LABEL(mw->detail_title), "");
    gtk_label_set_text(GTK_LABEL(mw->detail_url), "");
    gtk_label_set_text(GTK_LABEL(mw->detail_username), "");
    gtk_label_set_text(GTK_LABEL(mw->detail_password), "••••••••");
    gtk_label_set_text(GTK_LABEL(mw->detail_notes), "");
    gtk_label_set_text(GTK_LABEL(mw->detail_category), "");
    gtk_label_set_text(GTK_LABEL(mw->detail_totp), "");
    gtk_widget_set_visible(mw->detail_totp_row, FALSE);
}

static void mw_show_detail(MainWindow *mw, const char *uuid)
{
    void *db = session_get_db();
    if (db == NULL)
    {
        return;
    }

    Entry *e = db_entry_read(db, uuid);
    if (e == NULL)
    {
        return;
    }

    g_free(mw->selected_uuid);
    mw->selected_uuid = g_strdup(uuid);

    gtk_label_set_text(GTK_LABEL(mw->detail_title),
                       e->title ? e->title : "");
    gtk_label_set_text(GTK_LABEL(mw->detail_url),
                       e->url ? e->url : "");
    gtk_label_set_text(GTK_LABEL(mw->detail_username),
                       e->username ? e->username : "");
    gtk_label_set_text(GTK_LABEL(mw->detail_password), "••••••••");
    gtk_label_set_text(GTK_LABEL(mw->detail_notes),
                       e->notes ? e->notes : "");
    gtk_label_set_text(GTK_LABEL(mw->detail_category),
                       e->category ? e->category : "");

    /* TOTP */
    if (e->totp_secret != NULL && e->totp_secret[0] != '\0')
    {
        char totp_code[7];
        if (totp_generate(e->totp_secret, totp_code) == VAULTC_OK)
        {
            gtk_label_set_text(GTK_LABEL(mw->detail_totp), totp_code);
        }
        else
        {
            gtk_label_set_text(GTK_LABEL(mw->detail_totp), "Error");
        }
        gtk_widget_set_visible(mw->detail_totp_row, TRUE);
    }
    else
    {
        gtk_widget_set_visible(mw->detail_totp_row, FALSE);
    }

    db_free_entry(e);
}

/* ── Build detail pane ─────────────────────────────────────────────────────── */

static GtkWidget *make_detail_row(const char *label_text, GtkWidget **value)
{
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_margin_top(row, 4);
    gtk_widget_set_margin_bottom(row, 4);

    GtkWidget *label = gtk_label_new(label_text);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0f);
    gtk_widget_set_size_request(label, 100, -1);
    gtk_widget_add_css_class(label, "dim-label");
    gtk_box_append(GTK_BOX(row), label);

    *value = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(*value), 0.0f);
    gtk_label_set_selectable(GTK_LABEL(*value), TRUE);
    gtk_widget_set_hexpand(*value, TRUE);
    gtk_label_set_wrap(GTK_LABEL(*value), TRUE);
    gtk_box_append(GTK_BOX(row), *value);

    return row;
}

static GtkWidget *build_detail_pane(MainWindow *mw)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_margin_top(box, 16);
    gtk_widget_set_margin_bottom(box, 16);
    gtk_widget_set_margin_start(box, 16);
    gtk_widget_set_margin_end(box, 16);

    gtk_box_append(GTK_BOX(box),
                   make_detail_row("Title:", &mw->detail_title));
    gtk_box_append(GTK_BOX(box),
                   make_detail_row("URL:", &mw->detail_url));
    gtk_box_append(GTK_BOX(box),
                   make_detail_row("Username:", &mw->detail_username));
    gtk_box_append(GTK_BOX(box),
                   make_detail_row("Password:", &mw->detail_password));
    gtk_box_append(GTK_BOX(box),
                   make_detail_row("Notes:", &mw->detail_notes));
    gtk_box_append(GTK_BOX(box),
                   make_detail_row("Category:", &mw->detail_category));

    GtkWidget *totp_row = make_detail_row("TOTP:", &mw->detail_totp);
    gtk_widget_set_visible(totp_row, FALSE);
    gtk_box_append(GTK_BOX(box), totp_row);
    mw->detail_totp_row = totp_row;

    return box;
}

/* ── Refresh the entry list ────────────────────────────────────────────────── */

static void mw_refresh_list(MainWindow *mw)
{
    /* Clear existing rows */
    GtkWidget *child;
    while ((child = gtk_widget_get_first_child(mw->list_box)) != NULL)
    {
        gtk_list_box_remove(GTK_LIST_BOX(mw->list_box),
                            child);
    }

    if (mw->entries != NULL)
    {
        db_free_entry_list(mw->entries);
        mw->entries = NULL;
    }

    const char *query = gtk_editable_get_text(
        GTK_EDITABLE(mw->search_entry));
    if (query != NULL && query[0] == '\0')
    {
        query = NULL;
    }

    mw->entries = session_entry_list(query);
    if (mw->entries == NULL)
    {
        return;
    }

    for (size_t i = 0; i < mw->entries->count; i++)
    {
        GtkWidget *row_content = create_entry_row(mw->entries->items[i]);
        gtk_list_box_append(GTK_LIST_BOX(mw->list_box), row_content);
    }
}

/* ── Window destroy cleanup ────────────────────────────────────────────────── */

static void on_main_window_destroy(GtkWidget *widget, gpointer user_data)
{
    MainWindow *mw = user_data;
    (void)widget;

    if (mw->autolock_id > 0)
    {
        g_source_remove(mw->autolock_id);
    }

    if (mw->entries != NULL)
    {
        db_free_entry_list(mw->entries);
    }

    g_free(mw->selected_uuid);
    g_free(mw);
}

/* ── Public: show main window ──────────────────────────────────────────────── */

void ui_main_window_refresh(GtkWindow *window)
{
    if (window == NULL)
        return;

    MainWindow *mw = g_object_get_data(G_OBJECT(window), "main-window");
    if (mw != NULL)
        mw_refresh_list(mw);
}

void ui_show_main_window(GtkApplication *app)
{
    MainWindow *mw = g_new0(MainWindow, 1);
    mw->app = app;

    /* Window */
    GtkWidget *window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "VaultC");
    gtk_window_set_default_size(GTK_WINDOW(window), 900, 600);
    mw->window = GTK_WINDOW(window);

    /* store pointer so other modules can find it */
    g_object_set_data(G_OBJECT(window), "main-window", mw);

    /* Header bar */
    GtkWidget *header = gtk_header_bar_new();

    GtkWidget *lock_btn = gtk_button_new_from_icon_name(
        "system-lock-screen");
    gtk_widget_set_tooltip_text(lock_btn, "Lock Vault");
    g_signal_connect(lock_btn, "clicked",
                     G_CALLBACK(on_lock_button_clicked), mw);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(header), lock_btn);

    GtkWidget *add_btn = gtk_button_new_from_icon_name("list-add");
    gtk_widget_set_tooltip_text(add_btn, "Add Entry");
    g_signal_connect(add_btn, "clicked",
                     G_CALLBACK(on_add_button_clicked), mw);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(header), add_btn);

    GtkWidget *import_btn = gtk_button_new_from_icon_name(
        "document-open");
    gtk_widget_set_tooltip_text(import_btn, "Import CSV");
    g_signal_connect(import_btn, "clicked",
                     G_CALLBACK(on_import_button_clicked), mw);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), import_btn);

    GtkWidget *settings_btn = gtk_button_new_from_icon_name(
        "emblem-system");
    gtk_widget_set_tooltip_text(settings_btn, "Settings");
    g_signal_connect(settings_btn, "clicked",
                     G_CALLBACK(on_settings_button_clicked), mw);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), settings_btn);

    gtk_window_set_titlebar(GTK_WINDOW(window), header);

    /* Main paned layout */
    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_paned_set_position(GTK_PANED(paned), 350);
    gtk_window_set_child(GTK_WINDOW(window), paned);

    /* Left pane: search + list */
    GtkWidget *left_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

    GtkWidget *search_entry = gtk_search_entry_new();
    gtk_widget_set_margin_top(search_entry, 8);
    gtk_widget_set_margin_bottom(search_entry, 8);
    gtk_widget_set_margin_start(search_entry, 8);
    gtk_widget_set_margin_end(search_entry, 8);
    g_signal_connect(search_entry, "search-changed",
                     G_CALLBACK(on_search_changed), mw);
    gtk_box_append(GTK_BOX(left_box), search_entry);
    mw->search_entry = search_entry;

    /* Entry list in scrolled window */
    GtkWidget *scroll = gtk_scrolled_window_new();
    gtk_widget_set_vexpand(scroll, TRUE);
    GtkWidget *list_box = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(list_box),
                                    GTK_SELECTION_SINGLE);
    g_signal_connect(list_box, "row-selected",
                     G_CALLBACK(on_row_selected), mw);
    g_signal_connect(list_box, "row-activated",
                     G_CALLBACK(on_row_activated), mw);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), list_box);
    gtk_box_append(GTK_BOX(left_box), scroll);
    mw->list_box = list_box;

    gtk_paned_set_start_child(GTK_PANED(paned), left_box);
    gtk_paned_set_shrink_start_child(GTK_PANED(paned), FALSE);

    /* Right pane: detail view */
    GtkWidget *detail_scroll = gtk_scrolled_window_new();
    gtk_widget_set_hexpand(detail_scroll, TRUE);
    GtkWidget *detail_box = build_detail_pane(mw);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(detail_scroll),
                                  detail_box);
    mw->detail_box = detail_box;

    gtk_paned_set_end_child(GTK_PANED(paned), detail_scroll);
    gtk_paned_set_shrink_end_child(GTK_PANED(paned), FALSE);

    /* Destroy handler */
    g_signal_connect(window, "destroy",
                     G_CALLBACK(on_main_window_destroy), mw);

    /* Auto-lock timer */
    mw->autolock_id = g_timeout_add_seconds(
        DEFAULT_AUTOLOCK_SECONDS, on_autolock_timeout, mw);

    /* Populate entry list */
    mw_refresh_list(mw);

    gtk_window_present(GTK_WINDOW(window));
}
