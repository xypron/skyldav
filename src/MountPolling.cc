/* 
 * File:   MountPolling.c
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
 * @file MountPolling.c
 * @brief Poll /proc/mounts to detect mount events.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE // enable ppoll
#endif // _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L // enable nanosleep
#include <errno.h>
#include <features.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "listmounts.h"
#include "MountPolling.h"

#define SKYLD_POLLMOUNT_STATUS_INITIAL 0
#define SKYLD_POLLMOUNT_STATUS_RUNNING 1
#define SKYLD_POLLMOUNT_STATUS_STOPPING 2
#define SKYLD_POLLMOUNT_STATUS_FAILURE 3
#define SKYLD_POLLMOUNT_STATUS_SUCCESS 4


StringSet *MountPolling::nomarkfs = NULL;
StringSet *MountPolling::nomarkmnt = NULL;

/**
 * @brief Status of thread.
 */
static volatile sig_atomic_t status = SKYLD_POLLMOUNT_STATUS_INITIAL;

/**
 * @brief thread.
 */
static pthread_t thread;

/**
 * @brief Handles signal.
 * 
 * @param sig signal number
 * @param info signal information
 * @param context userlevel context (a pointer ucntext_t casted to void *)
 */
static void hdl(int sig, siginfo_t *info, void * context) {
    pid_t pid = getpid();
    if (pid == info->si_pid) {
        status = SKYLD_POLLMOUNT_STATUS_STOPPING;
    }
}

/**
 * @brief Thread listening to mount events.
 * 
 * @param ccbptr pointer to callback routine
 * @return pointer to int indicating success
 */
static void *run(void *cbptr) {
    /*
     * file descriptor
     */
    int mfd;
    /**
     * set of file descriptors to be monitored
     */
    struct pollfd fds;
    /**
     * number of file descriptors
     */
    nfds_t nfds = 1;
    /**
     * signal masks
     */
    sigset_t emptyset;
    sigset_t blockset;
    /*
     * number of structures with nonzero revents fields, 0 = timeout
     */
    int ret;
    /**
     * action to take when signal occurs
     */
    struct sigaction act;
    /**
     * Pointer to callback function.
     */
    skyld_pollmountscallbackptr cb = (skyld_pollmountscallbackptr) cbptr;

    status = SKYLD_POLLMOUNT_STATUS_INITIAL;

    // Block signals.
    sigemptyset(&blockset);
    sigaddset(&blockset, SIGINT);
    sigaddset(&blockset, SIGTERM);
    sigaddset(&blockset, SIGUSR1);
    ret = pthread_sigmask(SIG_BLOCK, &blockset, NULL);
    if (ret != 0) {
        fprintf(stderr, "Failure to set signal mask: %s\n", strerror(ret));
        status = SKYLD_POLLMOUNT_STATUS_FAILURE;
        return NULL;
    }

    // Set handler for SIGUSR1.
    act.sa_sigaction = hdl;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_SIGINFO | SA_NODEFER;
    if (sigaction(SIGUSR1, &act, NULL)) {
        fprintf(stderr, "Failure to set signal handler.\n");
        status = SKYLD_POLLMOUNT_STATUS_FAILURE;
        return NULL;
    }

    // Open file /proc/mounts.
    mfd = open("/proc/mounts", O_RDONLY, 0);
    if (mfd < 0) {
        perror("open(/proc/mounts)");
        status = SKYLD_POLLMOUNT_STATUS_FAILURE;
        return NULL;
    }
    fds.fd = mfd;
    fds.events = POLLERR | POLLPRI;
    fds.revents = 0;
    sigemptyset(&emptyset);
    status = SKYLD_POLLMOUNT_STATUS_RUNNING;
    while (status == SKYLD_POLLMOUNT_STATUS_RUNNING) {
        ret = ppoll(&fds, nfds, NULL, &emptyset);
        if (ret > 0) {
            if (fds.revents & POLLERR) {
                if (cb) {
                    (*cb)();
                }
            }
            fds.revents = 0;
        } else if (ret < 0) {
            if (errno != EINTR) {
                perror("ppoll failed");
                close(mfd);
                status = SKYLD_POLLMOUNT_STATUS_FAILURE;
                return NULL;
            }
        }
    }
    close(mfd);
    status = SKYLD_POLLMOUNT_STATUS_SUCCESS;
    return NULL;
}

/**
 * @brief Tracks mountevents.
 */
static void cb() {
    char *dir;
    char *type;

    printf("Mount event has occured.\n");
    do {
        if (listmountinit()) {
            break;
        }
        while (!listmountnext(&dir, &type)) {
            printf("%s (%s)\n", dir, type);
        }
    } while (0);
    listmountfinalize();
}

void MountPolling::init(StringSet *nomarkfs, StringSet * nomarkmnt) {
    MountPolling::nomarkfs = nomarkfs;
    MountPolling::nomarkmnt = nomarkmnt;
}

/**
 * @brief Starts polling of /proc/mounts.
 * 
 * @param cbptr pointer to callback function
 * @return on success return 0
 */
int MountPolling::start() {
    pthread_attr_t attr;
    int ret;
    struct timespec waiting_time_rem;
    struct timespec waiting_time_req;

    if (status == SKYLD_POLLMOUNT_STATUS_RUNNING) {
        fprintf(stderr, "Polling already running\n");
        return EXIT_FAILURE;
    }
    status = SKYLD_POLLMOUNT_STATUS_INITIAL;

    ret = pthread_attr_init(&attr);
    if (ret != 0) {
        fprintf(stderr, "Failure to set thread attributes: %s\n",
                strerror(ret));
        return EXIT_FAILURE;
    }
    ret = pthread_create(&thread, &attr, run, (void *) cb);
    if (ret != 0) {
        fprintf(stderr, "Failure to create thread: %s\n", strerror(ret));
        return EXIT_FAILURE;
    }
    waiting_time_req.tv_sec = 0;
    waiting_time_req.tv_nsec = 100;
    while (status == SKYLD_POLLMOUNT_STATUS_INITIAL) {
        nanosleep(&waiting_time_req, &waiting_time_rem);
    }
    if (status == SKYLD_POLLMOUNT_STATUS_FAILURE) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

/**
 * @brief Stop polling of /proc/mounts.
 * 
 * @return on success return 0.
 */
int MountPolling::stop() {
    void *result;
    int ret;

    if (status != SKYLD_POLLMOUNT_STATUS_RUNNING) {
        fprintf(stderr, "Polling not started.\n");
        return EXIT_FAILURE;
    }
    status = SKYLD_POLLMOUNT_STATUS_STOPPING;
    ret = pthread_kill(thread, SIGUSR1);
    if (ret != 0) {
        fprintf(stderr, "Failure to kill thread: %s\n", strerror(ret));
        return EXIT_FAILURE;
    }
    ret = (int) pthread_join(thread, &result);
    if (ret != 0) {
        fprintf(stderr, "Failure to join thread: %s\n", strerror(ret));
        return EXIT_FAILURE;
    }
    if (status != SKYLD_POLLMOUNT_STATUS_SUCCESS) {
        fprintf(stderr, "Ending thread signals failure.\n");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
