/*
 * VaultC — Add/Edit Entry Dialog
 * File: src/ui/ui_entry_dialog.c
 */

#include "ui_internal.h"

#include "vaultc/session.h"
#include "vaultc/db.h"
#include "vaultc/utils.h"
#include "vaultc/crypto.h"

#include <string.h>
#include <time.h>

/* ── Dialog state ──────────────────────────────────────────────────────────── */

typedef struct
{
    GtkWindow *dialog;
    GtkWindow *parent;
    char *uuid; /* NULL for new entry */

    /* Field widgets */
    GtkWidget *title_entry;
    GtkWidget *url_entry;
    GtkWidget *username_entry;
    GtkWidget *password_entry;
    GtkWidget *notes_view;
    GtkWidget *category_entry;
    GtkWidget *favorite_check;
    GtkWidget *totp_entry;
    GtkWidget *error_label;
} EntryDialog;

/* ── Save callback ─────────────────────────────────────────────────────────── */

static void on_save_clicked(GtkButton *btn, gpointer user_data)
{
    EntryDialog *dlg = user_data;
    (void)btn;

    const char *title = gtk_editable_get_text(
        GTK_EDITABLE(dlg->title_entry));

    if (title == NULL || title[0] == '\0')
    {
        gtk_label_set_text(GTK_LABEL(dlg->error_label),
                           "Title is required.");
        gtk_widget_set_visible(dlg->error_label, TRUE);
        return;
    }

    Entry entry;
    memset(&entry, 0, sizeof(entry));

    /* UUID: reuse existing or generate new */
    if (dlg->uuid != NULL)
    {
        strncpy(entry.uuid, dlg->uuid, VAULTC_UUID_LEN - 1);
        entry.uuid[VAULTC_UUID_LEN - 1] = '\0';
    }
    else
    {
        uuid_generate(entry.uuid);
    }

    /* Collect fields (cast away const — entry fields are read-only) */
    entry.title = (char *)title;
    entry.url = (char *)gtk_editable_get_text(
        GTK_EDITABLE(dlg->url_entry));
    entry.username = (char *)gtk_editable_get_text(
        GTK_EDITABLE(dlg->username_entry));
    entry.password = (char *)gtk_editable_get_text(
        GTK_EDITABLE(dlg->password_entry));

    /* Notes from GtkTextView */
    GtkTextBuffer *buf = gtk_text_view_get_buffer(
        GTK_TEXT_VIEW(dlg->notes_view));
    GtkTextIter start, end;
    gtk_text_buffer_get_bounds(buf, &start, &end);
    char *notes_text = gtk_text_buffer_get_text(buf, &start, &end, FALSE);
    entry.notes = notes_text;

    entry.category = (char *)gtk_editable_get_text(
        GTK_EDITABLE(dlg->category_entry));
    entry.totp_secret = (char *)gtk_editable_get_text(
        GTK_EDITABLE(dlg->totp_entry));
    entry.is_favorite = gtk_check_button_get_active(
                            GTK_CHECK_BUTTON(dlg->favorite_check))
                            ? 1
                            : 0;
    entry.source = "manual";

    int64_t now = (int64_t)time(NULL);
    entry.updated_at = now;

    VaultcError err;
    if (dlg->uuid != NULL)
    {
        err = session_entry_update(&entry);
    }
    else
    {
        entry.created_at = now;
        err = session_entry_create(&entry);
    }

    g_free(notes_text);

    if (err != VAULTC_OK)
    {
        gtk_label_set_text(GTK_LABEL(dlg->error_label),
                           vaultc_strerror(err));
        gtk_widget_set_visible(dlg->error_label, TRUE);
        return;
    }

    /* Persist vault to disk and trigger background sync upload */
    session_save();

    /* update the main window list before closing */
    ui_main_window_refresh(dlg->parent);

    gtk_window_destroy(dlg->dialog);
}

/* ── Generate button: open generator dialog ────────────────────────────────── */

static void on_generate_clicked(GtkButton *btn, gpointer user_data)
{
    EntryDialog *dlg = user_data;
    (void)btn;
    ui_show_generator_dialog(dlg->dialog,
                             GTK_EDITABLE(dlg->password_entry));
}

/* ── Delete callback ───────────────────────────────────────────────────────── */

static void on_delete_clicked(GtkButton *btn, gpointer user_data)
{
    EntryDialog *dlg = user_data;
    (void)btn;

    if (dlg->uuid == NULL)
    {
        return;
    }

    VaultcError derr = session_entry_delete(dlg->uuid);
    if (derr != VAULTC_OK)
    {
        /* show error? for now just refresh and close */
        ui_main_window_refresh(dlg->parent);
        gtk_window_destroy(dlg->dialog);
        return;
    }

    /* Persist vault to disk and trigger background sync upload */
    session_save();

    ui_main_window_refresh(dlg->parent);
    gtk_window_destroy(dlg->dialog);
}

/* ── Public: show the entry dialog ─────────────────────────────────────────── */

void ui_show_entry_dialog(GtkWindow *parent, const char *uuid)
{
    EntryDialog *dlg = g_new0(EntryDialog, 1);
    dlg->parent = parent;
    dlg->uuid = uuid ? g_strdup(uuid) : NULL;

    /* Window */
    GtkWidget *window = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(window),
                         uuid ? "Edit Entry" : "New Entry");
    gtk_window_set_default_size(GTK_WINDOW(window), 500, 550);
    gtk_window_set_transient_for(GTK_WINDOW(window), parent);
    gtk_window_set_modal(GTK_WINDOW(window), TRUE);
    dlg->dialog = GTK_WINDOW(window);

    /* Scrollable content */
    GtkWidget *scroll = gtk_scrolled_window_new();
    gtk_window_set_child(GTK_WINDOW(window), scroll);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_top(box, 16);
    gtk_widget_set_margin_bottom(box, 16);
    gtk_widget_set_margin_start(box, 20);
    gtk_widget_set_margin_end(box, 20);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), box);

    /* Title */
    gtk_box_append(GTK_BOX(box), gtk_label_new("Title *"));
    dlg->title_entry = gtk_entry_new();
    gtk_box_append(GTK_BOX(box), dlg->title_entry);

    /* URL */
    gtk_box_append(GTK_BOX(box), gtk_label_new("URL"));
    dlg->url_entry = gtk_entry_new();
    gtk_box_append(GTK_BOX(box), dlg->url_entry);

    /* Username */
    gtk_box_append(GTK_BOX(box), gtk_label_new("Username"));
    dlg->username_entry = gtk_entry_new();
    gtk_box_append(GTK_BOX(box), dlg->username_entry);

    /* Password + Generate button */
    gtk_box_append(GTK_BOX(box), gtk_label_new("Password"));
    GtkWidget *pw_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    dlg->password_entry = gtk_password_entry_new();
    gtk_password_entry_set_show_peek_icon(
        GTK_PASSWORD_ENTRY(dlg->password_entry), TRUE);
    gtk_widget_set_hexpand(dlg->password_entry, TRUE);
    gtk_box_append(GTK_BOX(pw_box), dlg->password_entry);

    GtkWidget *gen_btn = gtk_button_new_with_label("Generate");
    g_signal_connect(gen_btn, "clicked",
                     G_CALLBACK(on_generate_clicked), dlg);
    gtk_box_append(GTK_BOX(pw_box), gen_btn);
    gtk_box_append(GTK_BOX(box), pw_box);

    /* Notes (multiline) */
    gtk_box_append(GTK_BOX(box), gtk_label_new("Notes"));
    dlg->notes_view = gtk_text_view_new();
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(dlg->notes_view),
                                GTK_WRAP_WORD_CHAR);
    GtkWidget *notes_frame = gtk_frame_new(NULL);
    gtk_widget_set_size_request(notes_frame, -1, 80);
    gtk_frame_set_child(GTK_FRAME(notes_frame), dlg->notes_view);
    gtk_box_append(GTK_BOX(box), notes_frame);

    /* Category */
    gtk_box_append(GTK_BOX(box), gtk_label_new("Category"));
    dlg->category_entry = gtk_entry_new();
    gtk_editable_set_text(GTK_EDITABLE(dlg->category_entry), "General");
    gtk_box_append(GTK_BOX(box), dlg->category_entry);

    /* TOTP secret */
    gtk_box_append(GTK_BOX(box), gtk_label_new("TOTP Secret (Base32)"));
    dlg->totp_entry = gtk_entry_new();
    gtk_box_append(GTK_BOX(box), dlg->totp_entry);

    /* Favorite */
    dlg->favorite_check = gtk_check_button_new_with_label("Favorite");
    gtk_box_append(GTK_BOX(box), dlg->favorite_check);

    /* Error label */
    dlg->error_label = gtk_label_new("");
    gtk_widget_add_css_class(dlg->error_label, "error");
    gtk_widget_set_visible(dlg->error_label, FALSE);
    gtk_box_append(GTK_BOX(box), dlg->error_label);

    /* Buttons */
    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(btn_box, GTK_ALIGN_END);
    gtk_widget_set_margin_top(btn_box, 8);

    if (uuid != NULL)
    {
        GtkWidget *del_btn = gtk_button_new_with_label("Delete");
        gtk_widget_add_css_class(del_btn, "destructive-action");
        g_signal_connect(del_btn, "clicked",
                         G_CALLBACK(on_delete_clicked), dlg);
        gtk_box_append(GTK_BOX(btn_box), del_btn);
    }

    GtkWidget *cancel_btn = gtk_button_new_with_label("Cancel");
    g_signal_connect_swapped(cancel_btn, "clicked",
                             G_CALLBACK(gtk_window_destroy), window);
    gtk_box_append(GTK_BOX(btn_box), cancel_btn);

    GtkWidget *save_btn = gtk_button_new_with_label("Save");
    gtk_widget_add_css_class(save_btn, "suggested-action");
    g_signal_connect(save_btn, "clicked",
                     G_CALLBACK(on_save_clicked), dlg);
    gtk_box_append(GTK_BOX(btn_box), save_btn);

    gtk_box_append(GTK_BOX(box), btn_box);

    /* Populate fields if editing */
    if (uuid != NULL)
    {
        void *db = session_get_db();
        Entry *e = db ? db_entry_read(db, uuid) : NULL;
        if (e != NULL)
        {
            gtk_editable_set_text(GTK_EDITABLE(dlg->title_entry),
                                  e->title ? e->title : "");
            gtk_editable_set_text(GTK_EDITABLE(dlg->url_entry),
                                  e->url ? e->url : "");
            gtk_editable_set_text(GTK_EDITABLE(dlg->username_entry),
                                  e->username ? e->username : "");
            gtk_editable_set_text(GTK_EDITABLE(dlg->password_entry),
                                  e->password ? e->password : "");
            if (e->notes != NULL)
            {
                GtkTextBuffer *nbuf = gtk_text_view_get_buffer(
                    GTK_TEXT_VIEW(dlg->notes_view));
                gtk_text_buffer_set_text(nbuf, e->notes, -1);
            }
            gtk_editable_set_text(GTK_EDITABLE(dlg->category_entry),
                                  e->category ? e->category : "General");
            gtk_editable_set_text(GTK_EDITABLE(dlg->totp_entry),
                                  e->totp_secret ? e->totp_secret : "");
            gtk_check_button_set_active(
                GTK_CHECK_BUTTON(dlg->favorite_check),
                e->is_favorite ? TRUE : FALSE);
            db_free_entry(e);
        }
    }

    /* Cleanup on destroy */
    g_signal_connect_swapped(window, "destroy",
                             G_CALLBACK(g_free), dlg->uuid);
    g_signal_connect_swapped(window, "destroy",
                             G_CALLBACK(g_free), dlg);

    gtk_window_present(GTK_WINDOW(window));
}
