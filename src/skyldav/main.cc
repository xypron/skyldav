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
 * @file main.cc
 * @brief Online virus scanner.
 */
#include <sys/capability.h>
#include <errno.h>
#include <fcntl.h>
#include <iostream>
#include <signal.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "conf.h"
#include "config.h"
#include "Environment.h"
#include "FanotifyPolling.h"
#include "Messaging.h"
#include "skyldav.h"
#include "StringSet.h"

/**
 * @brief Callback function for reading configuration file.
 * @param key key value
 * @param value parameter value
 * @return success
 */
static int confcb(const char *key, const char *value, void *info) {
    Environment *e = (Environment *) info;
    int ret = 0;
    unsigned int cacheMaxSize;
    int nThread;

    if (e == NULL) {
        throw 0;
    }

    if (!strcmp(key, "CACHE_MAX_SIZE")) {
        std::stringstream ss(value);
        ss >> cacheMaxSize;
        if (ss.fail()) {
            ret = 1;
        }
        e->setCacheMaxSize(cacheMaxSize);
    } else if (!strcmp(key, "NOMARK_FS")) {
        e->getNoMarkFileSystems()->add(value);
    } else if (!strcmp(key, "NOMARK_MNT")) {
        e->getNoMarkMounts()->add(value);
    } else if (!strcmp(key, "LOCAL_FS")) {
        e->getLocalFileSystems()->add(value);
    } else if (!strcmp(key, "THREADS")) {
        std::stringstream ss(value);
        ss >> nThread;
        if (ss.fail()) {
            ret = 1;
        }
        e->setNumberOfThreads(nThread);
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
    int ret;

    fd = open(filename, O_CREAT | O_TRUNC | O_WRONLY,
            S_IRUSR | S_IWUSR);
    if (fd == -1) {
        syslog(LOG_ERR, "Cannot create pid file '%s'.", filename);
    }
    len = snprintf(buffer, sizeof (buffer), "%d", (int) getpid());
    ret = write(fd, buffer, len);
    syslog(LOG_ERR, "Cannot write pid file '%s'.", filename);
    if (ret == -1)
        close(fd);
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
static void authcheck(Environment *e) {
    if (!capable(CAP_SYS_ADMIN)) {
        fprintf(stderr,
                "Missing capability CAP_SYS_ADMIN.\n"
                "Call the program as root.\n");
        delete e;
        exit(EXIT_FAILURE);
    }
}

/**
 * @brief Daemonizes.
 */
static void daemonize(Environment *e) {
    pid_t pid;

    // Check if this process is already a daemon.
    if (getppid() == 1) {
        return;
    }
    pid = fork();
    if (pid == -1) {
        perror("Cannot fork");
        delete e;
        exit(EXIT_FAILURE);
    }
    if (pid != 0) {
        // Exit calling process.
        exit(EXIT_SUCCESS);
    }
    // Change working directory.
    if (chdir("/") == -1) {
        perror("Cannot change directory");
        delete e;
        exit(EXIT_FAILURE);
    }
    // Set the user file creation mask.
    umask(022);
    // Set new session ID
    if (setsid() == -1) {
        perror("Cannot create session");
    }
    // Redirect standard files
    if (NULL == freopen("/dev/null", "r", stdin)) {
        perror("Cannot redirect /dev/null to stdin");
    };
    if (NULL == freopen("/dev/null", "w", stdout)) {
        perror("Cannot redirect stdout to /dev/null");
    };
    if (NULL == freopen("/dev/null", "w", stderr)) {
        perror("Cannot redirect stderr to /dev/null");
    };
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
    // environment
    Environment *e;
    // running as daemon
    int daemonized = 0;
    // shall run as daemon
    int shalldaemonize = 0;
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
    // Fanotify polling object
    FanotifyPolling *fp;
    // Message level
    int messageLevel = Messaging::INFORMATION;
    // Number of threads
    int nThread;

    e = new Environment();

    // Set the number of threads to the number of available CPUs.
    nThread = sysconf(_SC_NPROCESSORS_ONLN);
    if (nThread < 1) {
        // Use at least one thread.
        nThread = 1;
    }
    e->setNumberOfThreads(nThread);

    // Analyze command line options.
    for (i = 1; i < argc; i++) {
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
            case 'm':
                i++;
                if (i < argc) {
                    std::istringstream(argv[i]) >> messageLevel;
                } else {
                    help();
                }
                if (messageLevel > Messaging::ERROR
                        || messageLevel < Messaging::DEBUG) {
                    help();
                }
                break;
            case 'v':
                version();
                ;
                break;
            default:
                help();
        }
    }

    // Parse configuration file.
    if (conf_parse(cfile, confcb, (void *) e)) {
        return EXIT_FAILURE;
    }

    // Check number of threads.
    if (nThread < 1) {
        fprintf(stderr,
                "At least one thread is needed for scanning.\n");
        return EXIT_FAILURE;
    }

    // Check authorization.
    authcheck(e);

    // Daemonize if requested.
    if (shalldaemonize) {
        daemonize(e);
        daemonized = 1;
    }

    Messaging::setLevel((Messaging::Level) messageLevel);

    Messaging::message(Messaging::DEBUG, "Starting on access scanning.");

    // Block signals.
    sigemptyset(&blockset);
    sigaddset(&blockset, SIGUSR1);
    if (sigprocmask(0 * SIG_BLOCK, &blockset, NULL) == -1) {
        Messaging::error("main, pthread_sigmask");
        return EXIT_FAILURE;
    }

    // Set handler for SIGTERM.
    act.sa_handler = hdl;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    if (sigaction(SIGTERM, &act, NULL)
            || sigaction(SIGINT, &act, NULL)
            || sigaction(SIGUSR1, &act, NULL)) {
        Messaging::error("main, sigaction");
        return EXIT_FAILURE;
    }

    try {
        fp = new FanotifyPolling(e);
    } catch (FanotifyPolling::Status ex) {
        Messaging::message(Messaging::ERROR,
                "Failure starting fanotify listener.");
        delete e;
        return EXIT_FAILURE;
    }

    Messaging::message(Messaging::INFORMATION, "On access scanning started.");
    if (daemonized) {
        pause();
    } else {
        printf("Press any key to terminate\n");
        getchar();
    }

    try {
        delete fp;
    } catch (FanotifyPolling::Status e) {
    }
    Messaging::message(Messaging::INFORMATION, "On access scanning stopped.");
    Messaging::teardown();
    delete e;
    printf("done\n");
    return EXIT_SUCCESS;
}
