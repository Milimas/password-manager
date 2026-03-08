/*
 * VaultC — Settings Dialog
 * File: src/ui/ui_settings_dialog.c
 *
 * Auto-lock timeout, clipboard clear delay, default pw length,
 * change master password, export vault warning.
 */

#include "ui_internal.h"

#include "vaultc/session.h"
#include "vaultc/crypto.h"

#include <string.h>

/* ── Dialog state ──────────────────────────────────────────────────────────── */

typedef struct
{
    GtkWindow *dialog;
    GtkWindow *parent;

    GtkWidget *autolock_dropdown;
    GtkWidget *clip_clear_spin;
    GtkWidget *default_pw_spin;

    /* Change password widgets */
    GtkWidget *old_pw_entry;
    GtkWidget *new_pw_entry;
    GtkWidget *confirm_pw_entry;
    GtkWidget *change_pw_btn;
    GtkWidget *change_pw_label;
    GtkWidget *change_pw_spinner;
} SettingsDialog;

/* ── Change password ───────────────────────────────────────────────────────── */

static void change_pw_thread(GTask *task, gpointer source,
                             gpointer task_data, GCancellable *cancellable)
{
    (void)source;
    (void)cancellable;

    char **passwords = task_data;
    VaultcError err = session_change_password(passwords[0], passwords[1]);
    g_task_return_pointer(task, GINT_TO_POINTER((int)err), NULL);
}

static void change_pw_data_free(gpointer data)
{
    char **passwords = data;
    if (passwords[0] != NULL)
    {
        crypto_secure_zero(passwords[0], strlen(passwords[0]));
        g_free(passwords[0]);
    }
    if (passwords[1] != NULL)
    {
        crypto_secure_zero(passwords[1], strlen(passwords[1]));
        g_free(passwords[1]);
    }
    g_free(passwords);
}

static void on_change_pw_done(GObject *source, GAsyncResult *res,
                              gpointer user_data)
{
    SettingsDialog *dlg = user_data;
    GTask *task = G_TASK(res);
    (void)source;

    VaultcError err = (VaultcError)GPOINTER_TO_INT(
        g_task_propagate_pointer(task, NULL));

    gtk_spinner_stop(GTK_SPINNER(dlg->change_pw_spinner));
    gtk_widget_set_visible(dlg->change_pw_spinner, FALSE);
    gtk_widget_set_sensitive(dlg->change_pw_btn, TRUE);

    if (err == VAULTC_OK)
    {
        gtk_label_set_text(GTK_LABEL(dlg->change_pw_label),
                           "Password changed successfully.");
        gtk_widget_add_css_class(dlg->change_pw_label, "success");
        gtk_widget_remove_css_class(dlg->change_pw_label, "error");
    }
    else
    {
        gtk_label_set_text(GTK_LABEL(dlg->change_pw_label),
                           err == VAULTC_ERR_BAD_PASSWORD
                               ? "Current password is incorrect."
                               : "Failed to change password.");
        gtk_widget_add_css_class(dlg->change_pw_label, "error");
        gtk_widget_remove_css_class(dlg->change_pw_label, "success");
    }
    gtk_widget_set_visible(dlg->change_pw_label, TRUE);

    /* Clear password fields */
    gtk_editable_set_text(GTK_EDITABLE(dlg->old_pw_entry), "");
    gtk_editable_set_text(GTK_EDITABLE(dlg->new_pw_entry), "");
    gtk_editable_set_text(GTK_EDITABLE(dlg->confirm_pw_entry), "");
}

static void on_change_pw_clicked(GtkButton *btn, gpointer user_data)
{
    SettingsDialog *dlg = user_data;
    (void)btn;

    const char *old_pw = gtk_editable_get_text(
        GTK_EDITABLE(dlg->old_pw_entry));
    const char *new_pw = gtk_editable_get_text(
        GTK_EDITABLE(dlg->new_pw_entry));
    const char *confirm = gtk_editable_get_text(
        GTK_EDITABLE(dlg->confirm_pw_entry));

    if (old_pw == NULL || old_pw[0] == '\0')
    {
        gtk_label_set_text(GTK_LABEL(dlg->change_pw_label),
                           "Enter current password.");
        gtk_widget_set_visible(dlg->change_pw_label, TRUE);
        return;
    }

    if (new_pw == NULL || new_pw[0] == '\0')
    {
        gtk_label_set_text(GTK_LABEL(dlg->change_pw_label),
                           "New password cannot be empty.");
        gtk_widget_set_visible(dlg->change_pw_label, TRUE);
        return;
    }

    if (strcmp(new_pw, confirm) != 0)
    {
        gtk_label_set_text(GTK_LABEL(dlg->change_pw_label),
                           "New passwords do not match.");
        gtk_widget_set_visible(dlg->change_pw_label, TRUE);
        return;
    }

    gtk_widget_set_sensitive(dlg->change_pw_btn, FALSE);
    gtk_widget_set_visible(dlg->change_pw_spinner, TRUE);
    gtk_spinner_start(GTK_SPINNER(dlg->change_pw_spinner));
    gtk_widget_set_visible(dlg->change_pw_label, FALSE);

    char **passwords = g_new0(char *, 2);
    passwords[0] = g_strdup(old_pw);
    passwords[1] = g_strdup(new_pw);

    GTask *task = g_task_new(NULL, NULL, on_change_pw_done, dlg);
    g_task_set_task_data(task, passwords, change_pw_data_free);
    g_task_run_in_thread(task, change_pw_thread);
    g_object_unref(task);
}

/* ── Public: show settings dialog ──────────────────────────────────────────── */

void ui_show_settings_dialog(GtkWindow *parent)
{
    SettingsDialog *dlg = g_new0(SettingsDialog, 1);
    dlg->parent = parent;

    /* Window */
    GtkWidget *window = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(window), "Settings");
    gtk_window_set_default_size(GTK_WINDOW(window), 450, 500);
    gtk_window_set_transient_for(GTK_WINDOW(window), parent);
    gtk_window_set_modal(GTK_WINDOW(window), TRUE);
    dlg->dialog = GTK_WINDOW(window);

    GtkWidget *scroll = gtk_scrolled_window_new();
    gtk_window_set_child(GTK_WINDOW(window), scroll);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_top(box, 20);
    gtk_widget_set_margin_bottom(box, 20);
    gtk_widget_set_margin_start(box, 20);
    gtk_widget_set_margin_end(box, 20);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), box);

    /* ── Auto-lock timeout ─────────────────────────────────────────────── */
    gtk_box_append(GTK_BOX(box), gtk_label_new("Auto-lock timeout:"));
    const char *autolock_items[] = {
        "1 minute", "5 minutes", "15 minutes", "30 minutes", "Never", NULL};
    dlg->autolock_dropdown = gtk_drop_down_new_from_strings(autolock_items);
    gtk_drop_down_set_selected(
        GTK_DROP_DOWN(dlg->autolock_dropdown), 1); /* default 5 min */
    gtk_box_append(GTK_BOX(box), dlg->autolock_dropdown);

    /* ── Clipboard clear delay ─────────────────────────────────────────── */
    GtkWidget *clip_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_append(GTK_BOX(clip_box),
                   gtk_label_new("Clipboard clear delay (seconds):"));
    dlg->clip_clear_spin = gtk_spin_button_new_with_range(
        10.0, 120.0, 5.0);
    gtk_spin_button_set_value(
        GTK_SPIN_BUTTON(dlg->clip_clear_spin), 30.0);
    gtk_box_append(GTK_BOX(clip_box), dlg->clip_clear_spin);
    gtk_box_append(GTK_BOX(box), clip_box);

    /* ── Default password length ───────────────────────────────────────── */
    GtkWidget *pwlen_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_append(GTK_BOX(pwlen_box),
                   gtk_label_new("Default password length:"));
    dlg->default_pw_spin = gtk_spin_button_new_with_range(
        8.0, 128.0, 1.0);
    gtk_spin_button_set_value(
        GTK_SPIN_BUTTON(dlg->default_pw_spin), 20.0);
    gtk_box_append(GTK_BOX(pwlen_box), dlg->default_pw_spin);
    gtk_box_append(GTK_BOX(box), pwlen_box);

    /* ── Separator ─────────────────────────────────────────────────────── */
    gtk_box_append(GTK_BOX(box), gtk_separator_new(
                                     GTK_ORIENTATION_HORIZONTAL));

    /* ── Change master password ────────────────────────────────────────── */
    GtkWidget *pw_section = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(pw_section),
                         "<b>Change Master Password</b>");
    gtk_label_set_xalign(GTK_LABEL(pw_section), 0.0f);
    gtk_box_append(GTK_BOX(box), pw_section);

    gtk_box_append(GTK_BOX(box), gtk_label_new("Current password:"));
    dlg->old_pw_entry = gtk_password_entry_new();
    gtk_password_entry_set_show_peek_icon(
        GTK_PASSWORD_ENTRY(dlg->old_pw_entry), TRUE);
    gtk_box_append(GTK_BOX(box), dlg->old_pw_entry);

    gtk_box_append(GTK_BOX(box), gtk_label_new("New password:"));
    dlg->new_pw_entry = gtk_password_entry_new();
    gtk_password_entry_set_show_peek_icon(
        GTK_PASSWORD_ENTRY(dlg->new_pw_entry), TRUE);
    gtk_box_append(GTK_BOX(box), dlg->new_pw_entry);

    gtk_box_append(GTK_BOX(box), gtk_label_new("Confirm new password:"));
    dlg->confirm_pw_entry = gtk_password_entry_new();
    gtk_password_entry_set_show_peek_icon(
        GTK_PASSWORD_ENTRY(dlg->confirm_pw_entry), TRUE);
    gtk_box_append(GTK_BOX(box), dlg->confirm_pw_entry);

    /* Change password result */
    dlg->change_pw_label = gtk_label_new("");
    gtk_widget_set_visible(dlg->change_pw_label, FALSE);
    gtk_box_append(GTK_BOX(box), dlg->change_pw_label);

    dlg->change_pw_spinner = gtk_spinner_new();
    gtk_widget_set_visible(dlg->change_pw_spinner, FALSE);
    gtk_box_append(GTK_BOX(box), dlg->change_pw_spinner);

    GtkWidget *change_btn = gtk_button_new_with_label("Change Password");
    gtk_widget_add_css_class(change_btn, "destructive-action");
    g_signal_connect(change_btn, "clicked",
                     G_CALLBACK(on_change_pw_clicked), dlg);
    gtk_box_append(GTK_BOX(box), change_btn);
    dlg->change_pw_btn = change_btn;

    /* Cleanup */
    g_signal_connect_swapped(window, "destroy",
                             G_CALLBACK(g_free), dlg);

    gtk_window_present(GTK_WINDOW(window));
}
