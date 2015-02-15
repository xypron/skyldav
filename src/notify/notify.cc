/*
 * File:   notify.c
 *
 * Copyright 2013 Heinrich Schuchardt <xypron.glpk@gmx.de>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/**
 * @file notify.cc
 * @brief Notify Skyld AV events.
 *
 * Sound depends on freedesktop-sound-theme
 */

#include <gtk/gtk.h>
#include <libnotify/notify.h>
#include <glib.h>
#include <canberra.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "config.h"
#include "notify.h"

#define RUNNING  1
#define STOPPING 2

volatile sig_atomic_t status;

static void sigint_handler(int sig) {
    write(0, "\nSTOPPING\n", 10);
    status = STOPPING;
}

/**
 * @brief Prints help message and exits.
 */
static void help() {
    printf("%s", HELP_TEXT);
    exit(EXIT_FAILURE);
}

/**
 * @brief Shows version information and exits.
 */
static void version() {
    printf("Skyld AV, version %s\n", VERSION);
    printf("%s", VERSION_TEXT);
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
    int i;
    NotifyNotification *n;
    char filename[] = "/run/skyldav/log";
    char application[] = "Skyld AV";
    char title[] = "Skyld AV";
    char body[2048];
    FILE *file;
    struct sigaction sa;

    // Analyze command line options.
    for (i = 1; i < argc; i++) {
        char *opt;

        opt = argv[i];
        if (*opt == '-') {
            opt++;
        } else {
            help();
        }
        if (*opt == '-') {
            opt++;
        }
        switch (*opt) {
            case 'v':
                version();
                break;
            default:
                help();
        }
    }

    printf("Skyld AV notifier %s\n", VERSION);
    printf("Exit with CTRL+C\n");

    file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "File '%s' not found\n", filename);
        return EXIT_FAILURE;
    }
    // position to end of file
    fseek(file, 0, SEEK_END);

    sa.sa_handler = sigint_handler;
    sa.sa_flags = 0; // or SA_RESTART
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        fclose(file);
        perror("sigaction");
        return EXIT_FAILURE;
    }

    ca_context *c;

    // initialize gtk
    gtk_init(&argc, &argv);

    // initialize notify
    notify_init(application);

    status = RUNNING;

    for (;;) {
        char *msg;

        msg = fgets(body, 2047, file);
        if (msg == NULL) {
            if (status != RUNNING) {
                break;
            }
            if (feof(file)) {
                usleep(500000);
            }
            if (ferror(file)) {
                perror("fgets");
            }
            continue;
        }

        // create a new notification
        switch (body[0]) {
            case '\0':
            case '\n':
                n = notify_notification_new(title, "<Empty message>",
                                            "dialog-information");
                break;
            case 'E':
                n = notify_notification_new(title, body + 1, "dialog-error");
                break;
            case 'W':
                n = notify_notification_new(title, body + 1, "dialog-warning");
                break;
            case 'I':
                n = notify_notification_new(title, body + 1, "dialog-information");
                break;
            default:
                n = notify_notification_new(title, body + 1, "dialog-information");
        }

        // set the timeout to 9000 ms
        notify_notification_set_timeout(n, 9000);

        // set the urgency level to critical
        notify_notification_set_urgency(n, NOTIFY_URGENCY_CRITICAL);

        // show the notification
        GError *error = NULL;
        notify_notification_show(n, &error);

        ca_context_create(&c);
        ca_context_play(c, 0,
                        CA_PROP_EVENT_ID, "dialog-warning",
                        CA_PROP_EVENT_DESCRIPTION, title,
                        NULL);
        usleep(500000);
    }

    fclose(file);

    return EXIT_SUCCESS;
}

