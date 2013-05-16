/* 
 * File:   pollfanotify.c
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
 * @file pollfanotify.c
 * @brief Poll fanotify events.
 */
#define _GNU_SOURCE // enable ppoll
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include "pollfanotify.h"
#include "virusscan.h"

#define SKYLD_POLLFANOTIFY_STATUS_INITIAL 0
#define SKYLD_POLLFANOTIFY_STATUS_RUNNING 1
#define SKYLD_POLLFANOTIFY_STATUS_STOPPING 2
#define SKYLD_POLLFANOTIFY_STATUS_FAILURE 3
#define SKYLD_POLLFANOTIFY_STATUS_SUCCESS 4
#define SKYLD_POLLFANOTIFY_BUFLEN 4096

/**
 * @brief File descriptor.
 */
int fd;
/**
 * @brief Status of thread.
 */
static volatile sig_atomic_t status;

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
        status = SKYLD_POLLFANOTIFY_STATUS_STOPPING;
    }
}

/**
 * @brief Thread listening to fanotify events.
 * 
 * @param ccbptr pointer to callback routine
 * @return pointer to int indicating success
 */
static void *run(void *cbptr) {
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
     * Properties of event file descriptors.
     */
    unsigned int event_f_flags = O_RDONLY | O_CLOEXEC | O_LARGEFILE;
    /**
     * Behavior of the fanotify file descriptor.
     */
    unsigned int flags = FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK
            | FAN_UNLIMITED_MARKS | FAN_UNLIMITED_QUEUE;
    /**
     * Pointer to callback function.
     */
    skyld_pollfanotifycallbackptr cb = (skyld_pollfanotifycallbackptr) cbptr;
    /**
     * Buffer.
     */
    char buf[SKYLD_POLLFANOTIFY_BUFLEN];

    // Thread shall not exit before SIGUSR1 occurs
    status = SKYLD_POLLFANOTIFY_STATUS_INITIAL;

    // Block signals.
    sigemptyset(&blockset);
    sigaddset(&blockset, SIGINT);
    sigaddset(&blockset, SIGTERM);
    sigaddset(&blockset, SIGUSR1);
    ret = pthread_sigmask(SIG_BLOCK, &blockset, NULL);
    if (ret != 0) {
        fprintf(stderr, "Failure to set signal mask: %s\n", strerror(ret));
        status = SKYLD_POLLFANOTIFY_STATUS_FAILURE;
        return NULL;
    }

    // Set handler for SIGUSR1.
    act.sa_sigaction = hdl;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_SIGINFO | SA_NODEFER;
    if (sigaction(SIGUSR1, &act, NULL)) {
        fprintf(stderr, "Failure to set signal handler.\n");
        status = SKYLD_POLLFANOTIFY_STATUS_FAILURE;
        return NULL;
    }

    fd = fanotify_init(flags, event_f_flags);
    if (fd == -1) {
        perror("fanotify_init");
        status = SKYLD_POLLFANOTIFY_STATUS_FAILURE;
        return NULL;
    }
    fds.fd = fd;
    fds.events = POLLIN | POLLERR;
    fds.revents = 0;
    sigemptyset(&emptyset);
    status = SKYLD_POLLFANOTIFY_STATUS_RUNNING;
    while (status == SKYLD_POLLFANOTIFY_STATUS_RUNNING) {
        ret = ppoll(&fds, nfds, NULL, &emptyset);
        if (ret > 0) {
            if (fds.revents & POLLIN) {
                for (;;) {
                    ret = read(fd, (void *) &buf, SKYLD_POLLFANOTIFY_BUFLEN);
                    if (ret > 0) {
                        if (cb) {
                            (*cb)(fd, &buf, ret);
                        }
                        break;
                    } else if (ret < 0) {
                        if (errno & (EINTR | EAGAIN | ETXTBSY | EWOULDBLOCK)) {
                            break;
                        }
                        perror("reading failed");
                        syslog(LOG_CRIT, "Reading from fanotiy failed.");
                        syslog(LOG_INFO, "Fanotiy thread stopped.");
                        close(fd);
                        status = SKYLD_POLLFANOTIFY_STATUS_FAILURE;
                        return NULL;
                    }
                }
            }
            fds.revents = 0;
        } else if (ret < 0) {
            if (errno != EINTR) {
                perror("ppoll failed");
                syslog(LOG_CRIT, "Polling fanotiy failed.");
                syslog(LOG_INFO, "Fanotiy thread stopped.");
                close(fd);
                status = SKYLD_POLLFANOTIFY_STATUS_FAILURE;
                return NULL;
            }
        }
    }
    syslog(LOG_INFO, "Fanotiy thread stopped.");
    close(fd);
    status = SKYLD_POLLFANOTIFY_STATUS_SUCCESS;
    return NULL;
}

/**
 * @brief Display fanotify event.
 */
void skyld_displayfanotify(const int fd, const void *buf, int len) {
    const struct fanotify_event_metadata *metadata = buf;
    char path[PATH_MAX];
    int path_len;
    int ret;
    struct stat statbuf;
    struct fanotify_response response;

    while (FAN_EVENT_OK(metadata, len)) {

        if (metadata->fd == FAN_NOFD) {
            printf("Received FAN_NOFD from fanotiy.");
            syslog(LOG_CRIT, "Received FAN_NOFD from fanotiy.");
            metadata = FAN_EVENT_NEXT(metadata, len);
            continue;
        }

        if (metadata->mask & FAN_ALL_PERM_EVENTS) {
            ret = fstat(metadata->fd, &statbuf);
            if (ret == -1) {
                fprintf(stderr, "Failure read status: %s\n", strerror(errno));
                syslog(LOG_CRIT, "Failure read status: %s", strerror(errno));
                close(metadata->fd);
                metadata = FAN_EVENT_NEXT(metadata, len);
                continue;
            }
            response.fd = metadata->fd;
            if (S_ISDIR(statbuf.st_mode)
                    || skyld_scan(metadata->fd) == SKYLD_SCANOK) {
                response.response = FAN_ALLOW;
            } else {
                response.response = FAN_DENY;

                if (metadata->fd >= 0) {
                    sprintf(path, "/proc/self/fd/%d", metadata->fd);
                    path_len = readlink(path, path, sizeof (path) - 1);
                    if (path_len > 0) {
                        path[path_len] = '\0';
                        printf("File %s\n\n", path);
                    }
                }
            }
            ret = write(fd, &response, sizeof (struct fanotify_response));
            if (ret == -1) {
                fprintf(stderr, "Failure to write response: %s\n",
                        strerror(errno));
                syslog(LOG_CRIT, "Failure to write response: %s",
                        strerror(errno));
            }
        }
        close(metadata->fd);
        fflush(stdout);
        metadata = FAN_EVENT_NEXT(metadata, len);
    }
    return;
}

/**
 * @brief Starts polling fanotify events.
 * @param cbptr callback function
 * @return success
 */
int skyld_pollfanotifystart(skyld_pollfanotifycallbackptr cbptr) {
    pthread_attr_t attr;
    int ret;
    struct timespec waiting_time_rem;
    struct timespec waiting_time_req;

    if (status == SKYLD_POLLFANOTIFY_STATUS_RUNNING) {
        fprintf(stderr, "Polling already running\n");
        return EXIT_FAILURE;
    }

    ret = pthread_attr_init(&attr);
    if (ret != 0) {
        fprintf(stderr, "Failure to set thread attributes: %s\n",
                strerror(ret));
        return EXIT_FAILURE;
    }
    ret = pthread_create(&thread, &attr, run, (void *) cbptr);
    if (ret != 0) {
        fprintf(stderr, "Failure to create thread: %s\n", strerror(ret));
        return EXIT_FAILURE;
    }
    waiting_time_req.tv_sec = 0;
    waiting_time_req.tv_nsec = 100;
    while (status == SKYLD_POLLFANOTIFY_STATUS_INITIAL) {
        nanosleep(&waiting_time_req, &waiting_time_rem);
    }
    if (status == SKYLD_POLLFANOTIFY_STATUS_FAILURE) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;

}

/**
 * @brief Marks a mount for polling fanotify events.
 * 
 * @param mount
 * @return success
 */
int skyld_pollfanotifymarkmount(const char *mount) {
    unsigned int flags = FAN_MARK_ADD | FAN_MARK_MOUNT;
    uint64_t mask = FAN_OPEN_PERM | FAN_CLOSE_WRITE;
    int dfd = AT_FDCWD;
    int ret;

    ret = fanotify_mark(fd, flags, mask, dfd, mount);
    if (ret != 0) {
        fprintf(stderr, "Failure to set mark: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

/**
 * @brief Stops polling fanotify events.
 * 
 * @return success
 */
int skyld_pollfanotifystop() {
    void *result;
    int ret;

    if (status != SKYLD_POLLFANOTIFY_STATUS_RUNNING) {
        fprintf(stderr, "Polling not started.\n");
        return EXIT_FAILURE;
    }
    status = SKYLD_POLLFANOTIFY_STATUS_STOPPING;
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
    if (status != SKYLD_POLLFANOTIFY_STATUS_SUCCESS) {
        fprintf(stderr, "Ending thread signals failure.\n");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}


