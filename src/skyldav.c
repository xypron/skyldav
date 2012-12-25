/* 
 * File:   main.c
 * 
 * Copyright 2012 Heinrich Schuchardt <xypron.glpk@gmx.de>
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

#include <sys/capability.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>
#include "pollfanotify.h"
#include "virusscan.h"

/**
 * Handles signal.
 * @param sig signal
 */
static void hdl(int sig) {
    if (sig == SIGINT) {
        fprintf(stderr, "Main received SIGINT\n");
    }
    if (sig == SIGTERM) {
        fprintf(stderr, "Main received SIGTERM\n");
    }
    if (sig == SIGUSR1) {
        fprintf(stderr, "Main received SIGUSR1\n");
    }
}

/**
 * Daemonize
 */
static void daemonize() {
    pid_t pid;

    // Check if this process is already a daemon.
    if (getppid() == 1) {
        return;
    }
    pid = fork();
    if (pid == -1) {
        perror("Cannot fork");
        exit(EXIT_FAILURE);
    }
    if (pid > 1) {
        // Exit calling process.
        exit(EXIT_SUCCESS);
    }
    // Change working directory.
    if (chdir("/") == -1) {
        perror("Cannot change directory");
        exit(EXIT_FAILURE);
    }
    // Set the user file creation mask to zero.
    umask(0);
    // Set new session ID
    if (setsid() == -1) {
        perror("Cannot create session");
    }
    // Redirect standard files
    freopen("/dev/null", "r", stdin);
    freopen("/dev/null", "w", stdout);
    freopen("/dev/null", "w", stderr);
}

/**
 * Check if the process has a capability.
 * @param cap capability
 * @return 1 if process has capability, else 0.
 */
static int capable(cap_value_t cap) {
    cap_t caps;
    cap_flag_value_t value;
    int ret = 0;
    caps = cap_get_proc();
    if (caps == NULL) {
        fprintf(stderr, "Cannot access capabilities\n");
        return 0;
    }
    if (cap_get_flag(caps, cap, CAP_EFFECTIVE, &value) == -1) {
        fprintf(stderr, "Cannot get capability 1.\n");
    } else if (value == CAP_SET) {
        ret = 1;
    }
    if (cap_free(caps)) {
        fprintf(stderr, "Failure to free capability state");
        ret = 0;
    };
    return ret;
}

/**
 * Main.
 * @param argc argument count
 * @param argv arguments
 * @return 
 */
int main(int argc, char *argv[]) {
    /**
     * running as daemon
     */
    int daemonized = 0;
    /**
     * retrun value
     */
    int ret;
    /**
     * action to take when signal occurs
     */
    struct sigaction act;
    /**
     * signal mask
     */
    sigset_t blockset;

    if (!capable(CAP_SYS_ADMIN)) {
        fprintf(stderr, "Missing capability CAP_SYS_ADMIN\n");
        return EXIT_FAILURE;
    }

    if (argc > 1 && 0 == strcmp(argv[1], "-d")) {
        daemonize();
        daemonized = 1;
    }

    // Open syslog
    setlogmask(LOG_UPTO(LOG_NOTICE));
    openlog("Skyld AV", 0, LOG_USER);

    syslog(LOG_NOTICE, "Starting on access scanning.");

    printf("Loading database\n");
    ret = skyld_scaninit();
    if (ret != SKYLD_SCANOK) {
        syslog(LOG_ERR, "Loading database failed.");
        return EXIT_FAILURE;
    }

    // Block signals.
    sigemptyset(&blockset);
    sigaddset(&blockset, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &blockset, NULL) == -1) {
        perror("pthread_sigmask");
        return EXIT_FAILURE;
    }

    // Set handler for SIGTERM.
    act.sa_handler = hdl;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    if (sigaction(SIGTERM, &act, NULL)
            || sigaction(SIGINT, &act, NULL)
            || sigaction(SIGUSR1, &act, NULL)) {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    ret = skyld_pollfanotifystart(*skyld_displayfanotify);
    if (ret != 0) {
        fprintf(stderr, "Failure starting mount listener.\n");
        syslog(LOG_ERR, "Failure starting mount listener.");
        return EXIT_FAILURE;
    }
    ret = skyld_pollfanotifymarkmount("/home");
    //    ret = skyld_pollfanotifymarkmount("/");
    if (ret != 0) {
        fprintf(stderr, "Failure setting mark.\n");
        syslog(LOG_ERR, "Failure setting mark.");
    } else {
        syslog(LOG_NOTICE, "On access scanning started.");
        if (daemonized) {
            pause();
        } else {
            printf("Press any key to terminate\n");
            getchar();
        }
    }

    ret = skyld_pollfanotifystop();

    ret = skyld_scanfinalize();
    syslog(LOG_NOTICE, "On access scanning stopped.");
    closelog();
    printf("done\n");
    if (ret != SKYLD_SCANOK) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
