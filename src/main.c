/*
 * VaultC — Application Entry Point
 * File: src/main.c
 */

#include <gtk/gtk.h>

#include "vaultc/crypto.h"

/* Defined in ui_app.c */
GtkApplication *ui_app_new(void);

int main(int argc, char **argv)
{
    /* Initialize libsodium before anything else */
    if (crypto_init() != VAULTC_OK)
    {
        g_printerr("Fatal: failed to initialize crypto library.\n");
        return 1;
    }

    GtkApplication *app = ui_app_new();
    int status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);

    return status;
}
