/*
 * VaultC — CSV Import Dialog
 * File: src/ui/ui_import_dialog.c
 *
 * Steps:
 * 1. File chooser (GtkFileDialog) — filter for *.csv
 * 2. Auto-detect format, show detected label
 * 3. "Import" button → progress feedback → ImportResult summary
 */

#include "ui_internal.h"

#include "vaultc/session.h"
#include "vaultc/importer.h"

/* ── Dialog state ──────────────────────────────────────────────────────────── */

typedef struct
{
    GtkWindow *dialog;
    GtkWindow *parent;
    GtkWidget *file_label;
    GtkWidget *format_label;
    GtkWidget *import_btn;
    GtkWidget *result_label;
    GtkWidget *spinner;
    char *file_path;
    ImportFormat format;
} ImportDialog;

/* ── Format name helper ────────────────────────────────────────────────────── */

static const char *format_name(ImportFormat fmt)
{
    switch (fmt)
    {
    case IMPORT_GOOGLE:
        return "Google Passwords";
    case IMPORT_FIREFOX:
        return "Firefox Lockwise";
    case IMPORT_IOS:
        return "iOS/iCloud Keychain";
    case IMPORT_BITWARDEN:
        return "Bitwarden";
    default:
        return "Unknown";
    }
}

/* ── Import thread ─────────────────────────────────────────────────────────── */

typedef struct
{
    char *path;
    ImportFormat format;
} ImportTaskData;

static void import_task_data_free(gpointer data)
{
    ImportTaskData *td = data;
    g_free(td->path);
    g_free(td);
}

static void import_thread_func(GTask *task, gpointer source,
                               gpointer task_data,
                               GCancellable *cancellable)
{
    (void)source;
    (void)cancellable;

    ImportTaskData *td = task_data;
    void *db = session_get_db();

    ImportResult *result = g_new0(ImportResult, 1);
    if (db == NULL)
    {
        result->errors = 1;
        g_task_return_pointer(task, result, g_free);
        return;
    }

    ImportResult r;
    switch (td->format)
    {
    case IMPORT_GOOGLE:
        r = import_google_csv(db, td->path);
        break;
    case IMPORT_FIREFOX:
        r = import_firefox_csv(db, td->path);
        break;
    case IMPORT_IOS:
        r = import_ios_csv(db, td->path);
        break;
    case IMPORT_BITWARDEN:
        r = import_bitwarden_csv(db, td->path);
        break;
    default:
        r.imported = 0;
        r.skipped_duplicates = 0;
        r.errors = 1;
        r.error_messages = NULL;
        r.format_detected = IMPORT_UNKNOWN;
        break;
    }

    *result = r;
    /* Save vault after import */
    (void)session_save();

    g_task_return_pointer(task, result, g_free);
}

static void on_import_done(GObject *source, GAsyncResult *res,
                           gpointer user_data)
{
    ImportDialog *dlg = user_data;
    GTask *task = G_TASK(res);
    (void)source;

    ImportResult *result = g_task_propagate_pointer(task, NULL);

    gtk_spinner_stop(GTK_SPINNER(dlg->spinner));
    gtk_widget_set_visible(dlg->spinner, FALSE);
    gtk_widget_set_sensitive(dlg->import_btn, TRUE);

    if (result != NULL)
    {
        char summary[256];
        snprintf(summary, sizeof(summary),
                 "Imported: %d  |  Skipped (duplicates): %d  |  Errors: %d",
                 result->imported, result->skipped_duplicates, result->errors);
        gtk_label_set_text(GTK_LABEL(dlg->result_label), summary);
        gtk_widget_set_visible(dlg->result_label, TRUE);
        g_free(result);
    }

    /* refresh main window list so new entries appear immediately */
    ui_main_window_refresh(dlg->parent);
}

/* ── Import button clicked ─────────────────────────────────────────────────── */

static void on_import_button_clicked(GtkButton *btn, gpointer user_data)
{
    ImportDialog *dlg = user_data;
    (void)btn;

    if (dlg->file_path == NULL || dlg->format == IMPORT_UNKNOWN)
    {
        return;
    }

    gtk_widget_set_sensitive(dlg->import_btn, FALSE);
    gtk_widget_set_visible(dlg->spinner, TRUE);
    gtk_spinner_start(GTK_SPINNER(dlg->spinner));
    gtk_widget_set_visible(dlg->result_label, FALSE);

    ImportTaskData *td = g_new0(ImportTaskData, 1);
    td->path = g_strdup(dlg->file_path);
    td->format = dlg->format;

    GTask *task = g_task_new(NULL, NULL, on_import_done, dlg);
    g_task_set_task_data(task, td, import_task_data_free);
    g_task_run_in_thread(task, import_thread_func);
    g_object_unref(task);
}

/* ── File chooser callback ─────────────────────────────────────────────────── */

static void on_file_dialog_response(GObject *source, GAsyncResult *res,
                                    gpointer user_data)
{
    ImportDialog *dlg = user_data;
    GtkFileDialog *fd = GTK_FILE_DIALOG(source);

    GFile *file = gtk_file_dialog_open_finish(fd, res, NULL);
    if (file == NULL)
    {
        return;
    }

    g_free(dlg->file_path);
    dlg->file_path = g_file_get_path(file);
    g_object_unref(file);

    gtk_label_set_text(GTK_LABEL(dlg->file_label), dlg->file_path);

    /* Auto-detect format */
    dlg->format = import_detect_format(dlg->file_path);

    if (dlg->format == IMPORT_UNKNOWN)
    {
        gtk_label_set_text(GTK_LABEL(dlg->format_label),
                           "Format: Unknown (unsupported)");
        gtk_widget_set_sensitive(dlg->import_btn, FALSE);
    }
    else
    {
        char fmt_text[128];
        snprintf(fmt_text, sizeof(fmt_text), "Format: %s",
                 format_name(dlg->format));
        gtk_label_set_text(GTK_LABEL(dlg->format_label), fmt_text);
        gtk_widget_set_sensitive(dlg->import_btn, TRUE);
    }
}

static void on_choose_file_clicked(GtkButton *btn, gpointer user_data)
{
    ImportDialog *dlg = user_data;
    (void)btn;

    GtkFileDialog *fd = gtk_file_dialog_new();
    gtk_file_dialog_set_title(fd, "Select CSV File");

    /* Filter for CSV files */
    GtkFileFilter *filter = gtk_file_filter_new();
    gtk_file_filter_set_name(filter, "CSV Files (*.csv)");
    gtk_file_filter_add_pattern(filter, "*.csv");
    GListStore *filters = g_list_store_new(GTK_TYPE_FILE_FILTER);
    g_list_store_append(filters, filter);
    gtk_file_dialog_set_filters(fd, G_LIST_MODEL(filters));
    g_object_unref(filter);
    g_object_unref(filters);

    gtk_file_dialog_open(fd, dlg->dialog, NULL,
                         on_file_dialog_response, dlg);
    g_object_unref(fd);
}

/* ── Public: show import dialog ────────────────────────────────────────────── */

void ui_show_import_dialog(GtkWindow *parent)
{
    ImportDialog *dlg = g_new0(ImportDialog, 1);
    dlg->parent = parent;

    /* Window */
    GtkWidget *window = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(window), "Import Passwords");
    gtk_window_set_default_size(GTK_WINDOW(window), 500, 300);
    gtk_window_set_transient_for(GTK_WINDOW(window), parent);
    gtk_window_set_modal(GTK_WINDOW(window), TRUE);
    dlg->dialog = GTK_WINDOW(window);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_top(box, 20);
    gtk_widget_set_margin_bottom(box, 20);
    gtk_widget_set_margin_start(box, 20);
    gtk_widget_set_margin_end(box, 20);
    gtk_window_set_child(GTK_WINDOW(window), box);

    /* Step 1: File chooser */
    GtkWidget *choose_btn = gtk_button_new_with_label(
        "Choose CSV File…");
    g_signal_connect(choose_btn, "clicked",
                     G_CALLBACK(on_choose_file_clicked), dlg);
    gtk_box_append(GTK_BOX(box), choose_btn);

    dlg->file_label = gtk_label_new("No file selected");
    gtk_label_set_xalign(GTK_LABEL(dlg->file_label), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(dlg->file_label),
                            PANGO_ELLIPSIZE_MIDDLE);
    gtk_box_append(GTK_BOX(box), dlg->file_label);

    /* Step 2: Format detection */
    dlg->format_label = gtk_label_new("Format: —");
    gtk_label_set_xalign(GTK_LABEL(dlg->format_label), 0.0f);
    gtk_box_append(GTK_BOX(box), dlg->format_label);

    /* Step 3: Import button + spinner */
    GtkWidget *action_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    dlg->import_btn = gtk_button_new_with_label("Import");
    gtk_widget_add_css_class(dlg->import_btn, "suggested-action");
    gtk_widget_set_sensitive(dlg->import_btn, FALSE);
    g_signal_connect(dlg->import_btn, "clicked",
                     G_CALLBACK(on_import_button_clicked), dlg);
    gtk_box_append(GTK_BOX(action_box), dlg->import_btn);

    dlg->spinner = gtk_spinner_new();
    gtk_widget_set_visible(dlg->spinner, FALSE);
    gtk_box_append(GTK_BOX(action_box), dlg->spinner);

    gtk_box_append(GTK_BOX(box), action_box);

    /* Result label */
    dlg->result_label = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(dlg->result_label), 0.0f);
    gtk_widget_set_visible(dlg->result_label, FALSE);
    gtk_box_append(GTK_BOX(box), dlg->result_label);

    /* Cleanup */
    g_signal_connect_swapped(window, "destroy",
                             G_CALLBACK(g_free), dlg->file_path);
    g_signal_connect_swapped(window, "destroy",
                             G_CALLBACK(g_free), dlg);

    gtk_window_present(GTK_WINDOW(window));
}
