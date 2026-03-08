/*
 * VaultC — Master Password Unlock Dialog
 * File: src/ui/ui_unlock_dialog.c
 *
 * Modal dialog that prompts for the master password.
 * Argon2id KDF runs in a GTask thread to avoid blocking the GTK main loop.
 */

#include "ui_internal.h"

#include "vaultc/session.h"

/* ── Dialog state ──────────────────────────────────────────────────────────── */

typedef struct
{
    GtkWindow *window;
    GtkWidget *pw_entry;
    GtkWidget *unlock_btn;
    GtkWidget *error_label;
    GtkWidget *spinner;
    GtkApplication *app;
} UnlockDialog;

/* ── Thread: vault open (Argon2id runs here) ───────────────────────────────── */

static void vault_open_thread_func(GTask *task, gpointer source,
                                   gpointer task_data,
                                   GCancellable *cancellable)
{
    (void)source;
    (void)cancellable;

    const char *pw = (const char *)task_data;
    VaultcError err = session_open_vault(pw);

    g_task_return_pointer(task, GINT_TO_POINTER((int)err), NULL);
}

/* ── Callback: vault open finished (runs on main thread) ───────────────────── */

static void on_vault_open_done(GObject *source, GAsyncResult *res,
                               gpointer user_data)
{
    UnlockDialog *dlg = user_data;
    GTask *task = G_TASK(res);
    (void)source;

    VaultcError err = (VaultcError)GPOINTER_TO_INT(
        g_task_propagate_pointer(task, NULL));

    gtk_spinner_stop(GTK_SPINNER(dlg->spinner));
    gtk_widget_set_visible(dlg->spinner, FALSE);

    if (err != VAULTC_OK)
    {
        gtk_label_set_text(GTK_LABEL(dlg->error_label),
                           "Wrong password. Please try again.");
        gtk_widget_set_visible(dlg->error_label, TRUE);
        gtk_widget_set_sensitive(dlg->pw_entry, TRUE);
        gtk_widget_set_sensitive(dlg->unlock_btn, TRUE);
        gtk_widget_grab_focus(dlg->pw_entry);
        return;
    }

    /* Success — destroy dialog and show main window */
    GtkApplication *app = dlg->app;
    gtk_window_destroy(dlg->window);

    ui_show_main_window(app);
}

/* ── Signal: Unlock button clicked ─────────────────────────────────────────── */

static void on_unlock_button_clicked(GtkButton *btn, gpointer user_data)
{
    UnlockDialog *dlg = user_data;
    (void)btn;

    const char *pw = gtk_editable_get_text(GTK_EDITABLE(dlg->pw_entry));

    if (pw == NULL || pw[0] == '\0')
    {
        gtk_label_set_text(GTK_LABEL(dlg->error_label),
                           "Password cannot be empty.");
        gtk_widget_set_visible(dlg->error_label, TRUE);
        return;
    }

    /* Disable input while Argon2id computes */
    gtk_widget_set_visible(dlg->error_label, FALSE);
    gtk_widget_set_sensitive(dlg->pw_entry, FALSE);
    gtk_widget_set_sensitive(dlg->unlock_btn, FALSE);
    gtk_widget_set_visible(dlg->spinner, TRUE);
    gtk_spinner_start(GTK_SPINNER(dlg->spinner));

    /* Run vault open in background thread */
    GTask *task = g_task_new(NULL, NULL, on_vault_open_done, dlg);
    g_task_set_task_data(task, g_strdup(pw), g_free);
    g_task_run_in_thread(task, vault_open_thread_func);
    g_object_unref(task);
}

/* ── Public: show the unlock dialog ────────────────────────────────────────── */

void ui_show_unlock_dialog(GtkApplication *app)
{
    UnlockDialog *dlg = g_new0(UnlockDialog, 1);
    dlg->app = app;

    /* Window */
    GtkWidget *window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "VaultC — Unlock");
    gtk_window_set_default_size(GTK_WINDOW(window), 400, 250);
    gtk_window_set_resizable(GTK_WINDOW(window), FALSE);
    dlg->window = GTK_WINDOW(window);

    /* Layout */
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_top(box, 30);
    gtk_widget_set_margin_bottom(box, 30);
    gtk_widget_set_margin_start(box, 40);
    gtk_widget_set_margin_end(box, 40);
    gtk_window_set_child(GTK_WINDOW(window), box);

    /* Title label */
    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title),
                         "<span size='x-large' weight='bold'>"
                         "🔒 VaultC</span>");
    gtk_box_append(GTK_BOX(box), title);

    /* Instruction */
    GtkWidget *label = gtk_label_new("Enter master password");
    gtk_box_append(GTK_BOX(box), label);

    /* Password entry (visibility off by default — GtkPasswordEntry) */
    GtkWidget *pw_entry = gtk_password_entry_new();
    gtk_password_entry_set_show_peek_icon(
        GTK_PASSWORD_ENTRY(pw_entry), TRUE);
    gtk_widget_set_hexpand(pw_entry, TRUE);
    gtk_box_append(GTK_BOX(box), pw_entry);
    dlg->pw_entry = pw_entry;

    /* Error label (hidden initially) */
    GtkWidget *error_label = gtk_label_new("");
    gtk_widget_add_css_class(error_label, "error");
    gtk_widget_set_visible(error_label, FALSE);
    gtk_box_append(GTK_BOX(box), error_label);
    dlg->error_label = error_label;

    /* Spinner (hidden initially) */
    GtkWidget *spinner = gtk_spinner_new();
    gtk_widget_set_visible(spinner, FALSE);
    gtk_box_append(GTK_BOX(box), spinner);
    dlg->spinner = spinner;

    /* Unlock button */
    GtkWidget *unlock_btn = gtk_button_new_with_label("Unlock");
    gtk_widget_add_css_class(unlock_btn, "suggested-action");
    g_signal_connect(unlock_btn, "clicked",
                     G_CALLBACK(on_unlock_button_clicked), dlg);
    gtk_box_append(GTK_BOX(box), unlock_btn);
    dlg->unlock_btn = unlock_btn;

    /* Activate on Enter in password field */
    g_signal_connect_swapped(pw_entry, "activate",
                             G_CALLBACK(gtk_widget_activate), unlock_btn);

    /* Free dialog struct when window is destroyed */
    g_signal_connect_swapped(window, "destroy", G_CALLBACK(g_free), dlg);

    gtk_window_present(GTK_WINDOW(window));
}
