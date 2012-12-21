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

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include "pollfanotify.h"
#include "virusscan.h"

/**
 * Flag that tells the program to exit.
 */
static volatile sig_atomic_t exit_request = 0;

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
 * Main.
 * @param argc argument count
 * @param argv arguments
 * @return 
 */
int main(int argc, char *argv[]) {
    int ret;
    /**
     * action to take when signal occurs
     */
    struct sigaction act;
    /**
     * signal mask
     */
    sigset_t blockset;

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
        printf("Press any key to terminate\n");
        getchar();
    }

    ret = skyld_pollfanotifystop();

    ret = skyld_scanfinalize();
    syslog(LOG_NOTICE, "On access scanning stopped.");
    closelog();
    if (ret != SKYLD_SCANOK) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}