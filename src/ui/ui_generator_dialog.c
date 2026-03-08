/*
 * VaultC — Password Generator Dialog
 * File: src/ui/ui_generator_dialog.c
 *
 * GtkScale for length, checkboxes for character classes,
 * exclude field, strength meter, regenerate + copy buttons.
 */

#include "ui_internal.h"

#include "vaultc/pwgen.h"
#include "vaultc/crypto.h"
#include "vaultc/utils.h"

#include <string.h>

/* ── Dialog state ──────────────────────────────────────────────────────────── */

typedef struct
{
    GtkWindow *dialog;
    GtkEditable *target; /* Entry to paste result into (nullable) */

    GtkWidget *length_scale;
    GtkWidget *length_label;
    GtkWidget *chk_upper;
    GtkWidget *chk_lower;
    GtkWidget *chk_digits;
    GtkWidget *chk_symbols;
    GtkWidget *exclude_entry;
    GtkWidget *result_label;
    GtkWidget *strength_bar;
    GtkWidget *strength_label;

    char *current_pw;
} GenDialog;

/* ── Forward declarations ──────────────────────────────────────────────────── */

static void gen_regenerate(GenDialog *dlg);

/* ── Strength bar names ────────────────────────────────────────────────────── */

static const char *strength_text(StrengthScore s)
{
    switch (s)
    {
    case STRENGTH_VERY_WEAK:
        return "Very Weak";
    case STRENGTH_WEAK:
        return "Weak";
    case STRENGTH_FAIR:
        return "Fair";
    case STRENGTH_STRONG:
        return "Strong";
    case STRENGTH_VERY_STRONG:
        return "Very Strong";
    default:
        return "";
    }
}

/* ── Regenerate password ───────────────────────────────────────────────────── */

static void gen_regenerate(GenDialog *dlg)
{
    /* Free previous password securely */
    if (dlg->current_pw != NULL)
    {
        crypto_secure_zero(dlg->current_pw, strlen(dlg->current_pw));
        g_free(dlg->current_pw);
        dlg->current_pw = NULL;
    }

    PwgenOptions opts;
    memset(&opts, 0, sizeof(opts));

    opts.length = (int)gtk_range_get_value(
        GTK_RANGE(dlg->length_scale));
    opts.use_uppercase = gtk_check_button_get_active(
        GTK_CHECK_BUTTON(dlg->chk_upper));
    opts.use_lowercase = gtk_check_button_get_active(
        GTK_CHECK_BUTTON(dlg->chk_lower));
    opts.use_digits = gtk_check_button_get_active(
        GTK_CHECK_BUTTON(dlg->chk_digits));
    opts.use_symbols = gtk_check_button_get_active(
        GTK_CHECK_BUTTON(dlg->chk_symbols));

    const char *exc = gtk_editable_get_text(
        GTK_EDITABLE(dlg->exclude_entry));
    opts.exclude_chars = (exc != NULL && exc[0] != '\0')
                             ? (char *)exc
                             : NULL;

    /* Ensure at least one class is enabled */
    if (!opts.use_uppercase && !opts.use_lowercase &&
        !opts.use_digits && !opts.use_symbols)
    {
        gtk_label_set_text(GTK_LABEL(dlg->result_label),
                           "(enable at least one character class)");
        gtk_level_bar_set_value(GTK_LEVEL_BAR(dlg->strength_bar), 0.0);
        gtk_label_set_text(GTK_LABEL(dlg->strength_label), "");
        return;
    }

    char *pw = pwgen_generate(&opts);
    if (pw == NULL)
    {
        gtk_label_set_text(GTK_LABEL(dlg->result_label),
                           "(generation failed)");
        return;
    }

    dlg->current_pw = g_strdup(pw);

    /* Display password */
    gtk_label_set_text(GTK_LABEL(dlg->result_label), pw);

    /* Strength meter */
    StrengthScore score = pwgen_check_strength(pw);
    double bar_val = ((double)score + 1.0) / 5.0;
    gtk_level_bar_set_value(GTK_LEVEL_BAR(dlg->strength_bar), bar_val);
    gtk_label_set_text(GTK_LABEL(dlg->strength_label),
                       strength_text(score));

    /* Clean up original */
    crypto_secure_zero(pw, strlen(pw));
    free(pw);
}

/* ── Signals ───────────────────────────────────────────────────────────────── */

static void on_regenerate_clicked(GtkButton *btn, gpointer user_data)
{
    (void)btn;
    gen_regenerate(user_data);
}

static void on_length_changed(GtkRange *range, gpointer user_data)
{
    GenDialog *dlg = user_data;
    int len = (int)gtk_range_get_value(range);
    char text[16];
    snprintf(text, sizeof(text), "%d", len);
    gtk_label_set_text(GTK_LABEL(dlg->length_label), text);
    gen_regenerate(dlg);
}

static void on_option_toggled(GtkCheckButton *chk, gpointer user_data)
{
    (void)chk;
    gen_regenerate(user_data);
}

static void on_copy_close_clicked(GtkButton *btn, gpointer user_data)
{
    GenDialog *dlg = user_data;
    (void)btn;

    if (dlg->current_pw != NULL)
    {
        /* If there's a target entry, paste into it */
        if (dlg->target != NULL)
        {
            gtk_editable_set_text(dlg->target, dlg->current_pw);
        }

        /* Also copy to clipboard */
        GdkDisplay *display = gdk_display_get_default();
        GdkClipboard *clipboard = gdk_display_get_clipboard(display);
        gdk_clipboard_set_text(clipboard, dlg->current_pw);
        clipboard_schedule_clear(30);
    }

    gtk_window_destroy(dlg->dialog);
}

/* ── Cleanup ───────────────────────────────────────────────────────────────── */

static void on_gen_dialog_destroy(GtkWidget *widget, gpointer user_data)
{
    GenDialog *dlg = user_data;
    (void)widget;

    if (dlg->current_pw != NULL)
    {
        crypto_secure_zero(dlg->current_pw, strlen(dlg->current_pw));
        g_free(dlg->current_pw);
    }
    g_free(dlg);
}

/* ── Public: show the generator dialog ─────────────────────────────────────── */

void ui_show_generator_dialog(GtkWindow *parent, GtkEditable *target)
{
    GenDialog *dlg = g_new0(GenDialog, 1);
    dlg->target = target;

    /* Window */
    GtkWidget *window = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(window), "Password Generator");
    gtk_window_set_default_size(GTK_WINDOW(window), 450, 400);
    gtk_window_set_transient_for(GTK_WINDOW(window), parent);
    gtk_window_set_modal(GTK_WINDOW(window), TRUE);
    dlg->dialog = GTK_WINDOW(window);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_top(box, 16);
    gtk_widget_set_margin_bottom(box, 16);
    gtk_widget_set_margin_start(box, 20);
    gtk_widget_set_margin_end(box, 20);
    gtk_window_set_child(GTK_WINDOW(window), box);

    /* Length slider */
    GtkWidget *len_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_append(GTK_BOX(len_box), gtk_label_new("Length:"));
    dlg->length_label = gtk_label_new("20");
    gtk_box_append(GTK_BOX(len_box), dlg->length_label);
    gtk_box_append(GTK_BOX(box), len_box);

    dlg->length_scale = gtk_scale_new_with_range(
        GTK_ORIENTATION_HORIZONTAL, 8.0, 64.0, 1.0);
    gtk_range_set_value(GTK_RANGE(dlg->length_scale), 20.0);
    gtk_scale_set_digits(GTK_SCALE(dlg->length_scale), 0);
    g_signal_connect(dlg->length_scale, "value-changed",
                     G_CALLBACK(on_length_changed), dlg);
    gtk_box_append(GTK_BOX(box), dlg->length_scale);

    /* Checkboxes */
    dlg->chk_upper = gtk_check_button_new_with_label("Uppercase (A-Z)");
    gtk_check_button_set_active(GTK_CHECK_BUTTON(dlg->chk_upper), TRUE);
    g_signal_connect(dlg->chk_upper, "toggled",
                     G_CALLBACK(on_option_toggled), dlg);
    gtk_box_append(GTK_BOX(box), dlg->chk_upper);

    dlg->chk_lower = gtk_check_button_new_with_label("Lowercase (a-z)");
    gtk_check_button_set_active(GTK_CHECK_BUTTON(dlg->chk_lower), TRUE);
    g_signal_connect(dlg->chk_lower, "toggled",
                     G_CALLBACK(on_option_toggled), dlg);
    gtk_box_append(GTK_BOX(box), dlg->chk_lower);

    dlg->chk_digits = gtk_check_button_new_with_label("Digits (0-9)");
    gtk_check_button_set_active(GTK_CHECK_BUTTON(dlg->chk_digits), TRUE);
    g_signal_connect(dlg->chk_digits, "toggled",
                     G_CALLBACK(on_option_toggled), dlg);
    gtk_box_append(GTK_BOX(box), dlg->chk_digits);

    dlg->chk_symbols = gtk_check_button_new_with_label("Symbols (!@#$…)");
    gtk_check_button_set_active(GTK_CHECK_BUTTON(dlg->chk_symbols), TRUE);
    g_signal_connect(dlg->chk_symbols, "toggled",
                     G_CALLBACK(on_option_toggled), dlg);
    gtk_box_append(GTK_BOX(box), dlg->chk_symbols);

    /* Exclude characters */
    gtk_box_append(GTK_BOX(box), gtk_label_new("Exclude characters:"));
    dlg->exclude_entry = gtk_entry_new();
    gtk_box_append(GTK_BOX(box), dlg->exclude_entry);

    /* Generated password label (large, monospace) */
    dlg->result_label = gtk_label_new("");
    gtk_label_set_selectable(GTK_LABEL(dlg->result_label), TRUE);
    gtk_label_set_wrap(GTK_LABEL(dlg->result_label), TRUE);
    gtk_widget_add_css_class(dlg->result_label, "monospace");
    gtk_widget_set_margin_top(dlg->result_label, 8);
    gtk_widget_set_margin_bottom(dlg->result_label, 8);
    gtk_box_append(GTK_BOX(box), dlg->result_label);

    /* Strength meter */
    dlg->strength_bar = gtk_level_bar_new_for_interval(0.0, 1.0);
    gtk_level_bar_set_mode(GTK_LEVEL_BAR(dlg->strength_bar),
                           GTK_LEVEL_BAR_MODE_CONTINUOUS);
    gtk_box_append(GTK_BOX(box), dlg->strength_bar);

    dlg->strength_label = gtk_label_new("");
    gtk_box_append(GTK_BOX(box), dlg->strength_label);

    /* Buttons */
    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(btn_box, GTK_ALIGN_END);
    gtk_widget_set_margin_top(btn_box, 8);

    GtkWidget *regen_btn = gtk_button_new_with_label("Regenerate");
    g_signal_connect(regen_btn, "clicked",
                     G_CALLBACK(on_regenerate_clicked), dlg);
    gtk_box_append(GTK_BOX(btn_box), regen_btn);

    GtkWidget *copy_btn = gtk_button_new_with_label("Copy & Close");
    gtk_widget_add_css_class(copy_btn, "suggested-action");
    g_signal_connect(copy_btn, "clicked",
                     G_CALLBACK(on_copy_close_clicked), dlg);
    gtk_box_append(GTK_BOX(btn_box), copy_btn);

    gtk_box_append(GTK_BOX(box), btn_box);

    /* Destroy handler */
    g_signal_connect(window, "destroy",
                     G_CALLBACK(on_gen_dialog_destroy), dlg);

    /* Generate initial password */
    gen_regenerate(dlg);

    gtk_window_present(GTK_WINDOW(window));
}
