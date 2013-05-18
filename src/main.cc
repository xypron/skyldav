/* 
 * File:   skyldav.c
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

/**
 * @file maincc
 * @brief Online virus scanner.
 */
#include <sys/capability.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "conf.h"
#include "pollfanotify.h"
#include "skyldav.h"
#include "StringSet.h"
#include "virusscan.h"

/**
 * @brief File systems which shall not be scanned.
 */
static StringSet nomarkfs;
/**
 * @brief Mounts that shall not be scanned.
 */
static StringSet nomarkmnt;
/**
 * File systems for local drives.
 */
static StringSet localfs;

/**
 * @brief Callback function for reading configuration file.
 * @param key key value
 * @param value parameter value
 * @return success
 */
static int confcb(const char *key, const char *value) {
    int ret = 0;
    if (!strcmp(key, "NOMARK_FS")) {
        nomarkfs.add(value);
    } else if (!strcmp(key, "NOMARK_MNT")) {
        nomarkmnt.add(value);
    } else if (!strcmp(key, "LOCAL_FS")) {
        localfs.add(value);
    } else {
        ret = 1;
    }
    return ret;
}

/**
 * @brief Handles signal.
 * 
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
 * @brief Creates pidfile for daemon.
 */
static void pidfile() {
    char buffer[40];
    int len;
    const char *filename = PID_FILE;
    int fd;
    fd = open(filename, O_CREAT | O_TRUNC | O_WRONLY,
            S_IRUSR | S_IWUSR);
    if (fd == -1) {
        syslog(LOG_ERR, "Cannot create pid file '%s'.", filename);
    }
    len = snprintf(buffer, sizeof (buffer), "%d", (int) getpid());
    write(fd, buffer, len);
    close(fd);
}

static void help() {
    printf("%s\n", HELP_TEXT);
    exit(EXIT_FAILURE);
}

/**
 * @brief Check if the process has a capability.
 * 
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
        fprintf(stderr, "Failure to free capability state\n");
        ret = 0;
    };
    return ret;
}

/**
 * @brief Checks authorization.
 */
static void authcheck() {
    if (!capable(CAP_SYS_ADMIN)) {
        fprintf(stderr, 
                "Missing capability CAP_SYS_ADMIN.\n"
                "Call the program as root.\n");
        exit(EXIT_FAILURE);
    }
}

/**
 * @brief Daemonizes.
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
    if (pid != 0) {
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
    pidfile();
}

/**
 * @brief Main.
 * 
 * @param argc argument count
 * @param argv arguments
 * @return success
 */
int main(int argc, char *argv[]) {
    // running as daemon
    int daemonized = 0;
    // shall run as daemon
    int shalldaemonize = 0;
    // return value
    int ret;
    // action to take when signal occurs
    struct sigaction act;
    // signal mask
    sigset_t blockset;
    // counter
    int i;
    // command line option
    char *opt;
    // configuration file
    char *cfile = (char *) CONF_FILE;

    // Analyze command line options.
    for (i = 1; i < argc; i++) {
        opt = argv[i];
        opt++;
        if (*argv[i] == '-') {
            switch (*opt) {
                case 'c':
                    i++;
                    if (i < argc) {
                        cfile = argv[i];
                    } else {
                        help();
                    }
                    break;
                case 'd':
                    shalldaemonize = 1;
                    break;
                default:
                    help();
            }
        }
    }
    
    // Parse configuration file
    if (conf_parse(cfile, confcb)) {
        return EXIT_FAILURE;
    }

    // Check authorization.
    authcheck();

    // Daemonize if requested.
    if (shalldaemonize) {
        daemonize();
        daemonized = 1;
    }

    // Open syslog.
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
