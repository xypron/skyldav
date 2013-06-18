/*
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

#define RUNNING  1
#define STOPPING 2

volatile sig_atomic_t status;

void sigint_handler(int sig) {
    write(0, "\nSTOPPING\n", 10);
    status = STOPPING;
    }

int main(int argc, char **argv)
{
    NotifyNotification *n;
    char filename[] = "/run/skyldav/log";
    char application[] = "Skyld AV";
    char title[] = "Skyld AV";
   
    char body[2048];

    char *msg;

    FILE *file;

    struct sigaction sa;

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
      perror("sigaction");
      return EXIT_FAILURE;
    }
    
    ca_context *c;
      
    // initialize gtk
    gtk_init(&argc,&argv);
   
    // initialize notify
    notify_init(application);

    status = RUNNING;
    
    for (;;) {

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
      switch(body[0]) {
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
      notify_notification_set_urgency (n, NOTIFY_URGENCY_CRITICAL);
   
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

