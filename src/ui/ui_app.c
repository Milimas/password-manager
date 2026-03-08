/*
 * VaultC — GtkApplication Setup and Signal Wiring
 * File: src/ui/ui_app.c
 */

#include "ui_internal.h"

#include "vaultc/session.h"
#include "vaultc/crypto.h"

/* ── Application activation callback ──────────────────────────────────────── */

static void on_activate(GtkApplication *app, gpointer user_data)
{
    (void)user_data;

    if (session_vault_exists())
    {
        ui_show_unlock_dialog(app);
    }
    else
    {
        ui_show_welcome_dialog(app);
    }
}

/* ── Public: create and run the GtkApplication ─────────────────────────────── */

GtkApplication *ui_app_new(void)
{
    GtkApplication *app = gtk_application_new(
        "com.vaultc.app", G_APPLICATION_DEFAULT_FLAGS);

    g_signal_connect(app, "activate", G_CALLBACK(on_activate), NULL);

    return app;
}

/* ── Welcome dialog (create new vault) ─────────────────────────────────────── */

typedef struct
{
    GtkWindow *window;
    GtkWidget *pw_entry;
    GtkWidget *pw_confirm;
    GtkWidget *error_label;
    GtkWidget *create_btn;
    GtkWidget *spinner;
    GtkApplication *app;
} WelcomeDialog;

static void on_welcome_vault_created(GObject *source, GAsyncResult *res,
                                     gpointer user_data)
{
    WelcomeDialog *dlg = user_data;
    GTask *task = G_TASK(res);
    (void)source;

    VaultcError err = (VaultcError)GPOINTER_TO_INT(g_task_propagate_pointer(task, NULL));

    gtk_spinner_stop(GTK_SPINNER(dlg->spinner));
    gtk_widget_set_visible(dlg->spinner, FALSE);

    if (err != VAULTC_OK)
    {
        gtk_label_set_text(GTK_LABEL(dlg->error_label),
                           "Failed to create vault.");
        gtk_widget_set_visible(dlg->error_label, TRUE);
        gtk_widget_set_sensitive(dlg->create_btn, TRUE);
        return;
    }

    GtkApplication *app = dlg->app;
    gtk_window_destroy(dlg->window);

    ui_show_main_window(app);
}

static void welcome_create_thread(GTask *task, gpointer source,
                                  gpointer task_data,
                                  GCancellable *cancellable)
{
    (void)source;
    (void)cancellable;

    const char *pw = (const char *)task_data;
    VaultcError err = session_create_vault(pw);

    g_task_return_pointer(task, GINT_TO_POINTER((int)err), NULL);
}

static void on_create_button_clicked(GtkButton *btn, gpointer user_data)
{
    WelcomeDialog *dlg = user_data;
    (void)btn;

    const char *pw = gtk_editable_get_text(GTK_EDITABLE(dlg->pw_entry));
    const char *confirm = gtk_editable_get_text(
        GTK_EDITABLE(dlg->pw_confirm));

    /* Validate */
    if (pw == NULL || pw[0] == '\0')
    {
        gtk_label_set_text(GTK_LABEL(dlg->error_label),
                           "Password cannot be empty.");
        gtk_widget_set_visible(dlg->error_label, TRUE);
        return;
    }

    if (strcmp(pw, confirm) != 0)
    {
        gtk_label_set_text(GTK_LABEL(dlg->error_label),
                           "Passwords do not match.");
        gtk_widget_set_visible(dlg->error_label, TRUE);
        return;
    }

    gtk_widget_set_visible(dlg->error_label, FALSE);
    gtk_widget_set_sensitive(dlg->create_btn, FALSE);
    gtk_widget_set_visible(dlg->spinner, TRUE);
    gtk_spinner_start(GTK_SPINNER(dlg->spinner));

    GTask *task = g_task_new(NULL, NULL, on_welcome_vault_created, dlg);
    g_task_set_task_data(task, g_strdup(pw), g_free);
    g_task_run_in_thread(task, welcome_create_thread);
    g_object_unref(task);
}

void ui_show_welcome_dialog(GtkApplication *app)
{
    WelcomeDialog *dlg = g_new0(WelcomeDialog, 1);
    dlg->app = app;

    /* Window */
    GtkWidget *window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "VaultC — Create Vault");
    gtk_window_set_default_size(GTK_WINDOW(window), 400, 300);
    gtk_window_set_resizable(GTK_WINDOW(window), FALSE);
    dlg->window = GTK_WINDOW(window);

    /* Layout */
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_top(box, 30);
    gtk_widget_set_margin_bottom(box, 30);
    gtk_widget_set_margin_start(box, 40);
    gtk_widget_set_margin_end(box, 40);
    gtk_window_set_child(GTK_WINDOW(window), box);

    /* Title */
    GtkWidget *title = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title),
                         "<span size='x-large' weight='bold'>"
                         "Welcome to VaultC</span>");
    gtk_box_append(GTK_BOX(box), title);

    GtkWidget *subtitle = gtk_label_new(
        "Create a master password to secure your vault.");
    gtk_label_set_wrap(GTK_LABEL(subtitle), TRUE);
    gtk_box_append(GTK_BOX(box), subtitle);

    /* Password entry */
    GtkWidget *pw_entry = gtk_password_entry_new();
    gtk_password_entry_set_show_peek_icon(
        GTK_PASSWORD_ENTRY(pw_entry), TRUE);
    gtk_widget_set_hexpand(pw_entry, TRUE);
    gtk_accessible_update_property(GTK_ACCESSIBLE(pw_entry),
                                   GTK_ACCESSIBLE_PROPERTY_LABEL,
                                   "Master password", -1);
    gtk_box_append(GTK_BOX(box), pw_entry);
    dlg->pw_entry = pw_entry;

    /* Confirm password */
    GtkWidget *pw_confirm = gtk_password_entry_new();
    gtk_password_entry_set_show_peek_icon(
        GTK_PASSWORD_ENTRY(pw_confirm), TRUE);
    gtk_widget_set_hexpand(pw_confirm, TRUE);
    gtk_accessible_update_property(GTK_ACCESSIBLE(pw_confirm),
                                   GTK_ACCESSIBLE_PROPERTY_LABEL,
                                   "Confirm password", -1);
    gtk_box_append(GTK_BOX(box), pw_confirm);
    dlg->pw_confirm = pw_confirm;

    /* Error label */
    GtkWidget *error_label = gtk_label_new("");
    gtk_widget_add_css_class(error_label, "error");
    gtk_widget_set_visible(error_label, FALSE);
    gtk_box_append(GTK_BOX(box), error_label);
    dlg->error_label = error_label;

    /* Spinner */
    GtkWidget *spinner = gtk_spinner_new();
    gtk_widget_set_visible(spinner, FALSE);
    gtk_box_append(GTK_BOX(box), spinner);
    dlg->spinner = spinner;

    /* Create button */
    GtkWidget *create_btn = gtk_button_new_with_label("Create Vault");
    gtk_widget_add_css_class(create_btn, "suggested-action");
    g_signal_connect(create_btn, "clicked",
                     G_CALLBACK(on_create_button_clicked), dlg);
    gtk_box_append(GTK_BOX(box), create_btn);
    dlg->create_btn = create_btn;

    /* Free dialog struct when window is destroyed */
    g_signal_connect_swapped(window, "destroy", G_CALLBACK(g_free), dlg);

    gtk_window_present(GTK_WINDOW(window));
}
