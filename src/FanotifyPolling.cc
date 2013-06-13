/* 
 * File:   FanotifyPolling.cc
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
 * @file FanotifyPolling.cc
 * @brief Poll fanotify events.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <malloc.h>
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
#include "FanotifyPolling.h"
#include "ThreadPool.h"
#include "VirusScan.h"

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
 * @brief mutex
 */
pthread_mutex_t mutex_response;

/**
 * @brief Thread pool for virus scanning
 */
static ThreadPool *tp;

/**
 * @brief Virus scanner.
 */
static VirusScan *virusScan;

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
    /*
     * number of structures with nonzero revents fields, 0 = timeout
     */
    int ret;
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

    status = SKYLD_POLLFANOTIFY_STATUS_INITIAL;

    fd = fanotify_init(flags, event_f_flags);
    if (fd == -1) {
        perror("fanotify_init");
        status = SKYLD_POLLFANOTIFY_STATUS_FAILURE;
        return NULL;
    }

    fds.fd = fd;
    fds.events = POLLIN | POLLERR;
    fds.revents = 0;

    status = SKYLD_POLLFANOTIFY_STATUS_RUNNING;
    // Continue while the status is not changed.
    while (status == SKYLD_POLLFANOTIFY_STATUS_RUNNING) {
        // Poll for 10 ms. Then recheck status.
        ret = poll(&fds, nfds, 1000);
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
                perror("poll failed");
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
 * @brief Scans a file.
 */
void* scanFile(void *workitem) {
    int ret;
    struct ScanTask *task = (struct ScanTask *) workitem;
    struct fanotify_response response;
    pid_t pid;
    char path[PATH_MAX];
    int path_len;
    struct stat statbuf;

    if (task->metadata.mask & FAN_ALL_PERM_EVENTS) {
        ret = fstat(task->metadata.fd, &statbuf);
        if (ret == -1) {
            fprintf(stderr, "Failure read status: %s\n", strerror(errno));
            syslog(LOG_CRIT, "Failure read status: %s", strerror(errno));
        } else {
            response.fd = task->metadata.fd;
            // For same process always allow.
            pid = getpid();
            if (pid == task->metadata.pid) {
                response.response = FAN_ALLOW;
                // For directories always allow.
            } else if (!S_ISREG(statbuf.st_mode)) {
                response.response = FAN_ALLOW;
            } else if (virusScan->scan(task->metadata.fd)
                    == VirusScan::SCANOK) {
                response.response = FAN_ALLOW;
            } else {
                response.response = FAN_DENY;

                if (task->metadata.fd >= 0) {
                    sprintf(path, "/proc/self/fd/%d", task->metadata.fd);
                    path_len = readlink(path, path, sizeof (path) - 1);
                    if (path_len > 0) {
                        path[path_len] = '\0';
                        printf("File %s\n\n", path);
                    }
                }
            }
            ret = skyld_fanotifywriteresponse(fd, response);
        }
    }
    close(task->metadata.fd);
    free(task);

    fflush(stdout);

    return NULL;
}

/**
 * @brief Display fanotify event.
 */
void skyld_displayfanotify(const int fd, const void *buf, int len) {
    const struct fanotify_event_metadata *metadata =
            (const struct fanotify_event_metadata *) buf;
    int ret;
    struct fanotify_response response;
    struct ScanTask *task;

    while (FAN_EVENT_OK(metadata, len)) {
        if (metadata->fd == FAN_NOFD) {
            printf("Received FAN_NOFD from fanotiy.");
            syslog(LOG_CRIT, "Received FAN_NOFD from fanotiy.");
            metadata = FAN_EVENT_NEXT(metadata, len);
            continue;
        }

        ret = fstat(task->metadata.fd, &statbuf);
        if (ret == -1) {
            fprintf(stderr, "Failure read status: %s\n", strerror(errno));
            syslog(LOG_CRIT, "Failure read status: %s", strerror(errno));
        } else {
            response.fd = task->metadata.fd;
            pid = getpid();
            if (pid == task->metadata.pid) {
                // For same process always allow.
                response.response = FAN_ALLOW;
                ret = skyld_fanotifywriteresponse(fd, response);
                close(metadata->fd);
            } else if (!S_ISREG(statbuf.st_mode)) {
                // For directories always allow.
                response.response = FAN_ALLOW;
                ret = skyld_fanotifywriteresponse(fd, response);
                close(metadata->fd);
            } else {
                task = (struct ScanTask *) malloc(sizeof (struct ScanTask));
                if (task == NULL) {
                    fprintf(stderr, "Out of memory\n");
                    response.fd = metadata->fd;
                    response.response = FAN_ALLOW;
                    ret = skyld_fanotifywriteresponse(fd, response);
                    close(metadata->fd);
                } else {
                    task->metadata = *metadata;
                    task->fd = fd;
                    tp->add((void *) task);
                }
            }
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
    int skyld_pollfanotifystart(int nThread) {
        pthread_attr_t attr;
        int ret;
        struct timespec waiting_time_rem;
        struct timespec waiting_time_req;

        if (status == SKYLD_POLLFANOTIFY_STATUS_RUNNING) {
            fprintf(stderr, "Polling already running\n");
            return EXIT_FAILURE;
        }

        printf("Loading database\n");
        try {
            virusScan = new VirusScan();
        } catch (enum VirusScan::Status e) {
            fprintf(stderr, "Loading database failed.\n");
            syslog(LOG_ERR, "Loading database failed.");
            return EXIT_FAILURE;
        }

        ret = pthread_mutex_init(&mutex_response, NULL);
        if (ret != 0) {
            fprintf(stderr, "Failure to set intialize mutex: %s\n",
                    strerror(ret));
            return EXIT_FAILURE;
        }

        tp = new ThreadPool(nThread, scanFile);

        ret = pthread_attr_init(&attr);
        if (ret != 0) {
            fprintf(stderr, "Failure to set thread attributes: %s\n",
                    strerror(ret));
            return EXIT_FAILURE;
        }
        ret = pthread_create(&thread, &attr, run, (void *) &skyld_displayfanotify);
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
            fprintf(stderr, "Failure to set mark on '%s': %i - %s\n",
                    mount, errno, strerror(errno));
            return EXIT_FAILURE;
        }
        syslog(LOG_NOTICE, "Now watching: %s\n", mount);
        return EXIT_SUCCESS;
    }

    /**
     * @brief Removes a mount from polling fanotify events.
     * 
     * @param mount
     * @return success
     */
    int skyld_pollfanotifyunmarkmount(const char *mount) {
        unsigned int flags = FAN_MARK_REMOVE | FAN_MARK_MOUNT;
        uint64_t mask = FAN_OPEN_PERM | FAN_CLOSE_WRITE;
        int dfd = AT_FDCWD;
        int ret;

        ret = fanotify_mark(fd, flags, mask, dfd, mount);
        if (ret != 0 && errno != ENOENT) {
            fprintf(stderr, "Failure to remove mark from '%s': %i - %s\n",
                    mount, errno, strerror(errno));
            return EXIT_FAILURE;
        }
        syslog(LOG_NOTICE, "Stopped watching: %s\n", mount);
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
        int success = EXIT_SUCCESS;

        if (status != SKYLD_POLLFANOTIFY_STATUS_RUNNING) {
            fprintf(stderr, "Polling not started.\n");
            return EXIT_FAILURE;
        }
        status = SKYLD_POLLFANOTIFY_STATUS_STOPPING;
        ret = (int) pthread_join(thread, &result);
        if (ret != 0) {
            fprintf(stderr, "Failure to join thread: %s\n", strerror(ret));
            success = EXIT_FAILURE;
        } else if (status != SKYLD_POLLFANOTIFY_STATUS_SUCCESS) {
            fprintf(stderr, "Ending thread signals failure.\n");
            success = EXIT_FAILURE;
        }

        // Delete thread pool.
        delete tp;

        if (pthread_mutex_destroy(&mutex_response)) {
            fprintf(stderr, "Failure destroying mutex: %s\n", strerror(ret));
            success = EXIT_FAILURE;
        }

        try {
            delete virusScan;
        } catch (enum VirusScan::Status e) {
            fprintf(stderr, "Failure unloading virus scanner\n");
            success = EXIT_FAILURE;
        }

        return success;
    }

    /**
     * @brief Writes fanotify response
     * @param fd fanotify file descriptor
     * @param response response
     * @return success = 0
     */
    int skyld_fanotifywriteresponse(const int fd,
            const struct fanotify_response response) {
        int ret = 0;

        pthread_mutex_lock(&mutex_response);
        ret = write(fd, &response, sizeof (struct fanotify_response));
        if (ret == -1) {
            fprintf(stderr, "Failure to write response: %s\n",
                    strerror(errno));
            syslog(LOG_CRIT, "Failure to write response: %s",
                    strerror(errno));
            ret = 1;
        } else {
            ret = 0;
        }
        pthread_mutex_unlock(&mutex_response);
        return ret;
    }