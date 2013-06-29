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
#include <signal.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include "FanotifyPolling.h"
#include "Messaging.h"

#define SKYLD_POLLFANOTIFY_BUFLEN 4096

/**
 * @brief Thread listening to fanotify events.
 * 
 * @param ccbptr pointer to callback routine
 * @return NULL
 */
void *FanotifyPolling::run(void *obj) {

    /**
     * Fanotify polling object.
     */
    FanotifyPolling *fp;
    /**
     * @brief File descriptor.
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
     * Buffer.
     */
    char buf[SKYLD_POLLFANOTIFY_BUFLEN];

    // Copy fanotify object
    if (obj) {
        fp = (FanotifyPolling *) obj;
    } else {
        return NULL;
    }

    fds.fd = fp->fd;
    fds.events = POLLIN | POLLERR;
    fds.revents = 0;

    fp->status = RUNNING;
    // Continue while the status is not changed.
    while (fp->status == RUNNING) {
        // Poll for 10 ms. Then recheck status.
        ret = poll(&fds, nfds, 1000);
        if (ret > 0) {
            if (fds.revents & POLLIN) {
                for (;;) {
                    ret = read(fp->fd, (void *) &buf,
                            SKYLD_POLLFANOTIFY_BUFLEN);
                    if (ret > 0) {
                        fp->analyze(&buf, ret);
                        break;
                    } else if (ret < 0) {
                        if (errno & (EINTR | EAGAIN | ETXTBSY | EWOULDBLOCK)) {
                            break;
                        }
                        std::stringstream msg;
                        msg << "Reading from fanotify failed: "
                                << strerror(errno);
                        Messaging::message(Messaging::ERROR, msg.str());
                        Messaging::message(Messaging::WARNING,
                                "Fanotiy thread stopped.");
                        fp->status = FAILURE;
                        return NULL;
                    }
                }
            }
            fds.revents = 0;
        } else if (ret < 0) {
            if (errno != EINTR) {
                std::stringstream msg;
                msg << "Poll failed: "
                        << strerror(errno);
                Messaging::message(Messaging::ERROR, msg.str());
                Messaging::message(Messaging::WARNING,
                        "Fanotiy thread stopped.");
                fp->status = FAILURE;
                return NULL;
            }
        }
    }
    Messaging::message(Messaging::DEBUG, "Fanotiy thread stopped.");
    fp->status = SUCCESS;
    return NULL;
}

/**
 * @brief Scans a file.
 */
void* FanotifyPolling::scanFile(void *workitem) {
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
            std::stringstream msg;
            msg << "scanFile: failure to read file status: "
                    << strerror(errno);
            Messaging::message(Messaging::ERROR, msg.str());
        } else {
            response.fd = task->metadata.fd;
            // For same process always allow.
            pid = getpid();
            if (pid == task->metadata.pid) {
                response.response = FAN_ALLOW;
                // For directories always allow.
            } else if (!S_ISREG(statbuf.st_mode)) {
                response.response = FAN_ALLOW;
            } else if (task->fp->virusScan->scan(task->metadata.fd)
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
                        std::stringstream msg;
                        msg << "Access to file \"" << path << "\" denied.";
                        Messaging::message(Messaging::WARNING, msg.str());
                    }
                }
            }
            ret = task->fp->writeResponse(response);
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
void FanotifyPolling::analyze(const void *buf, int len) {
    const struct fanotify_event_metadata *metadata =
            (const struct fanotify_event_metadata *) buf;
    int ret;
    pid_t pid;
    struct stat statbuf;
    struct fanotify_response response;
    struct ScanTask *task;

    while (FAN_EVENT_OK(metadata, len)) {
        if (metadata->fd == FAN_NOFD) {
            Messaging::message(Messaging::ERROR,
                    "Received FAN_NOFD from fanotiy.");
            metadata = FAN_EVENT_NEXT(metadata, len);
            continue;
        }

        response.fd = metadata->fd;
        response.response = FAN_ALLOW;
        pid = getpid();
        if (pid == metadata->pid) {
            // For same process always allow.
            ret = writeResponse(response);
            close(metadata->fd);
        } else {
            // read file status
            ret = fstat(metadata->fd, &statbuf);
            if (ret == -1) {
                std::stringstream msg;
                msg << "scanFile: failure to read file status: "
                        << strerror(errno);
                Messaging::message(Messaging::ERROR, msg.str());
                ret = writeResponse(response);
                close(metadata->fd);
            } else if (!S_ISREG(statbuf.st_mode)) {
                // For directories always allow.
                ret = writeResponse(response);
                close(metadata->fd);
            } else {
                task = (struct ScanTask *) malloc(sizeof (struct ScanTask));
                if (task == NULL) {
                    Messaging::message(Messaging::ERROR, "Out of memory\n");
                    response.fd = metadata->fd;
                    response.response = FAN_ALLOW;
                    ret = writeResponse(response);
                    close(metadata->fd);
                } else {
                    task->metadata = *metadata;
                    task->fp = this;
                    tp->add((void *) task);
                }
            }
        }
        fflush(stdout);
        metadata = FAN_EVENT_NEXT(metadata, len);
    }
    return;
}

/**
 * @brief Starts polling fanotify events.
 * @param env environment
 * @return success
 */
FanotifyPolling::FanotifyPolling(Environment *env) {
    int ret;
    struct timespec waiting_time_rem;
    struct timespec waiting_time_req;
    
    e = env;

    status = INITIAL;

    Messaging::message(Messaging::DEBUG, "Loading virus database\n");
    try {
        virusScan = new VirusScan();
    } catch (enum VirusScan::Status e) {
        Messaging::message(Messaging::ERROR, "Loading database failed.\n");
        throw FAILURE;
    }

    ret = pthread_mutex_init(&mutex_response, NULL);
    if (ret != 0) {
        std::stringstream msg;
        msg << "Failure to intialize mutex: " << strerror(ret);
        Messaging::message(Messaging::ERROR, msg.str());
        throw FAILURE;
    }

    tp = new ThreadPool(e->getNumberOfThreads(), scanFile);

    ret = fanotifyOpen();
    if (ret != 0) {
        throw FAILURE;
    }

    ret = pthread_create(&thread, NULL, run, (void *) this);
    if (ret != 0) {
        std::stringstream msg;
        msg << "Failure to create thread: " << strerror(ret);
        Messaging::message(Messaging::ERROR, msg.str());
        throw FAILURE;
    }
    waiting_time_req.tv_sec = 0;
    waiting_time_req.tv_nsec = 100;
    while (status == INITIAL) {
        nanosleep(&waiting_time_req, &waiting_time_rem);
    }
    if (status == FAILURE) {
        throw FAILURE;
    }

    try {
        mp = new MountPolling(fd, e);
    } catch (MountPolling::Status e) {
        throw FAILURE;
    }
}

/**
 * @brief Stops polling fanotify events.
 * 
 * @return success
 */
FanotifyPolling::~FanotifyPolling() {
    void *result;
    int ret;
    enum Status success = SUCCESS;

    if (status != RUNNING) {
        Messaging::message(Messaging::ERROR, "Polling not started.\n");
        throw FAILURE;
    }

    // Stop the mount polling thread.
    try {
        if (mp) {
            delete mp;
        }
    } catch (MountPolling::Status e) {
        throw FAILURE;
    }

    // Stop the fanotify polling thread.
    status = STOPPING;
    ret = (int) pthread_join(thread, &result);
    if (ret != 0) {
        std::stringstream msg;
        msg << "Failure to joing thread: " << strerror(ret);
        Messaging::message(Messaging::ERROR, msg.str());
        success = FAILURE;
    } else if (status != SUCCESS) {
        Messaging::message(Messaging::ERROR,
                "Ending thread signals failure.\n");
        success = FAILURE;
    }

    // Close the fanotify file descriptor.
    fanotifyClose();

    // Delete thread pool.
    delete tp;

    // Destroy the mutex.
    if (pthread_mutex_destroy(&mutex_response)) {
        std::stringstream msg;
        msg << "Failure destroying thread: " << strerror(ret);
        Messaging::message(Messaging::ERROR, msg.str());
        success = FAILURE;
    }

    // Unload the virus scanner.
    try {
        delete virusScan;
    } catch (enum VirusScan::Status e) {
        Messaging::message(Messaging::ERROR,
                "Failure unloading virus scanner\n");
        success = FAILURE;
    }
    if (success != SUCCESS) {
        throw FAILURE;
    }
}

/**
 * @brief Writes fanotify response
 * @param fd fanotify file descriptor
 * @param response response
 * @return success = 0
 */
int FanotifyPolling::writeResponse(const struct fanotify_response response) {
    int ret = 0;

    pthread_mutex_lock(&mutex_response);
    ret = write(fd, &response, sizeof (struct fanotify_response));
    if (ret == -1 && errno != ENOENT) {
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

/**
 * Opens fanotify file descriptor.
 * 
 * @return success = 0;
 */
int FanotifyPolling::fanotifyOpen() {
    /**
     * Properties of event file descriptors.
     */
    unsigned int event_f_flags = O_RDONLY | O_CLOEXEC | O_LARGEFILE;
    /**
     * Behavior of the fanotify file descriptor.
     */
    unsigned int flags = FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK
            | FAN_UNLIMITED_MARKS | FAN_UNLIMITED_QUEUE;

    fd = fanotify_init(flags, event_f_flags);
    if (fd == -1) {
        std::stringstream msg;
        msg << "fanotifyOpen: " << strerror(errno);
        Messaging::message(Messaging::ERROR, msg.str());
        status = FAILURE;
        return -1;
    } else {
        return 0;
    }
}

/**
 * @brief Closes fanotify file descriptor.
 * 
 * @return success = 0
 */
int FanotifyPolling::fanotifyClose() {
    int ret = close(fd);
    if (ret == -1) {
        status = FAILURE;
        std::stringstream msg;
        msg << "fanotifyClose: " << strerror(errno);
        Messaging::message(Messaging::ERROR, msg.str());
        return -1;
    } else {
        return 0;
    }
}

/**
 * @brief Marks a mount for polling fanotify events.
 * 
 * @param mount
 * @return success
 */
int FanotifyPolling::markMount(int fd, const char *mount) {
    unsigned int flags = FAN_MARK_ADD | FAN_MARK_MOUNT;
    uint64_t mask = FAN_OPEN_PERM | FAN_CLOSE_WRITE;
    int dfd = AT_FDCWD;
    int ret;

    ret = fanotify_mark(fd, flags, mask, dfd, mount);
    if (ret != 0) {
        std::stringstream msg;
        msg << "Failure to set mark on '" << mount << "': " << strerror(errno);
        Messaging::message(Messaging::ERROR, msg.str());
        return EXIT_FAILURE;
    }
    std::stringstream msg;
    msg << "Now watching: " << mount;
    Messaging::message(Messaging::DEBUG, msg.str());
    return EXIT_SUCCESS;
}

/**
 * @brief Removes a mount from polling fanotify events.
 * 
 * @param mount
 * @return success
 */
int FanotifyPolling::unmarkMount(int fd, const char *mount) {
    unsigned int flags = FAN_MARK_REMOVE | FAN_MARK_MOUNT;
    uint64_t mask = FAN_OPEN_PERM | FAN_CLOSE_WRITE;
    int dfd = AT_FDCWD;
    int ret;

    ret = fanotify_mark(fd, flags, mask, dfd, mount);
    if (ret != 0 && errno != ENOENT) {
        std::stringstream msg;
        msg << "Failure to remove mark from '"
                << mount << "': " << strerror(errno);
        Messaging::message(Messaging::ERROR, msg.str());
        return EXIT_FAILURE;
    }
    std::stringstream msg;
    msg << "Stopped watching: " << mount;
    Messaging::message(Messaging::DEBUG, msg.str());
    return EXIT_SUCCESS;
}

