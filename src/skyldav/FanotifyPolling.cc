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
#include <linux/fcntl.h>
#include <linux/limits.h>
#include <malloc.h>
#include <poll.h>
#include <signal.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <sys/types.h>
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
    /**
     * Buffer.
     */
    char buf[SKYLD_POLLFANOTIFY_BUFLEN];

    // Copy fanotify object
    if (obj) {
        fp = static_cast<FanotifyPolling *> (obj);
    } else {
        return NULL;
    }

    fds.fd = fp->fd;
    fds.events = POLLIN;
    fds.revents = 0;

    fp->status = RUNNING;
    // Continue while the status is not changed.
    while (fp->status == RUNNING) {
        /*
         * number of structures with nonzero revents fields, 0 = timeout
         */
        int ret;
        char errbuf[256];
        // Poll for 1 s. Then recheck status.
        ret = poll(&fds, nfds, 1000);
        if (ret > 0) {
            if (fds.revents & POLLIN) {
                for (;;) {
                    ret = read(fp->fd, (void *) &buf,
                               SKYLD_POLLFANOTIFY_BUFLEN);
                    if (ret > 0) {
                        fp->handleFanotifyEvents(&buf, ret);
                        break;
                    } else if (ret < 0) {
                        if (errno & (EINTR | EAGAIN | ETXTBSY | EWOULDBLOCK)) {
                            break;
                        }
                        std::stringstream msg;
                        msg << "Reading from fanotify failed: "
                            << strerror_r(errno, errbuf, sizeof (errbuf));
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
                    << strerror_r(errno, errbuf, sizeof (errbuf));
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
 * @brief Check if file is in exclude path.
 *
 * @param fd file descriptor
 * @return 1 if in exclude path.
 */
int FanotifyPolling::exclude(const int fd) {
    int path_len;
    char path[PATH_MAX + 1];
    StringSet *exclude;
    StringSet::iterator pos;
    std::string fname;

    // Get absolute file path.
    snprintf(path, sizeof (path), "/proc/self/fd/%d", fd);
    path_len = readlink(path, path, sizeof (path) - 1);
    if (path_len < 0) {
        path_len = 0;
    }
    path[path_len] = '\0';
    fname = path;

    // Search in exclude paths.
    exclude = e->getExcludePaths();

    for (pos = exclude->begin(); pos != exclude->end(); ++pos) {
        std::string *str = *pos;

        if (0 == fname.compare(0, str->size(), *str)) {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Scans a file.
 */
void* FanotifyPolling::scanFile(void *workitem) {
    struct ScanTask *task = (struct ScanTask *) workitem;
    struct fanotify_response response;
    pid_t pid;
    struct stat statbuf;

    if (task->metadata.mask & FAN_ALL_PERM_EVENTS) {
        int ret;
        ret = fstat(task->metadata.fd, &statbuf);
        if (ret == -1) {
            char errbuf[256];
            std::stringstream msg;
            msg << "scanFile: failure to read file status: "
                << strerror_r(errno, errbuf, sizeof (errbuf));
            Messaging::message(Messaging::ERROR, msg.str());
        } else {
            response.fd = task->metadata.fd;
            // For same process always allow.
            pid = getpid();
            if (pid == task->metadata.pid) {
                // for Skyld AV process always allow.
                response.response = FAN_ALLOW;
            } else if (!S_ISREG(statbuf.st_mode)) {
                // For directories always allow.
                response.response = FAN_ALLOW;
            } else if (task->fp->exclude(task->metadata.fd)) {
                // In exclude path.
                response.response = FAN_ALLOW;
            } else if (task->fp->virusScan->scan(task->metadata.fd)
                       == VirusScan::SCANOK) {
                // No virus found.
                response.response = FAN_ALLOW;
            } else {
                response.response = FAN_DENY;
            }
            task->fp->writeResponse(response, 1);
        }
    }
    close(task->metadata.fd);
    free(task);

    fflush(stdout);

    return NULL;
}

/**
 * @brief Handle fanotify events.
 *
 * @param buf buffer with events
 * @param len length of the buffer
 */
void FanotifyPolling::handleFanotifyEvent(
    const struct fanotify_event_metadata *metadata) {

    int ret;
    pid_t pid;
    struct stat statbuf;
    struct fanotify_response response = {
        .fd = metadata->fd,
        .response = FAN_DENY,
    };
    int tobeclosed = 1;

    ret = fstat(metadata->fd, &statbuf);
    if (ret == -1) {
        std::stringstream msg;
        char errbuf[256];
        msg << "analyze: failure to read file status: "
            << strerror_r(errno, errbuf, sizeof (errbuf));
        Messaging::message(Messaging::ERROR, msg.str());
        ret = writeResponse(response, 0);
    } else {
        if (metadata->mask & FAN_CLOSE_WRITE) {
            e->getScanCache()->remove(&statbuf);
        }
        if (metadata->mask & FAN_MODIFY) {
            if (S_ISREG(statbuf.st_mode)) {
                // It is a file. Do not receive further MODIFY events.
                ret = fanotify_mark(fd, FAN_MARK_ADD
                                    | FAN_MARK_IGNORED_MASK
                                    | FAN_MARK_IGNORED_SURV_MODIFY, FAN_MODIFY,
                                    metadata->fd, NULL);
                if (ret == -1) {
                    perror("analyze: fanotify_mark");
                }
                e->getScanCache()->remove(&statbuf);
            }
        }
        if (metadata->mask & FAN_OPEN_PERM) {
            response.fd = metadata->fd;
            response.response = FAN_ALLOW;
            pid = getpid();
            if (pid == metadata->pid) {
                // for Skyld AV process always allow.
                ret = writeResponse(response, 0);
            } else if (!S_ISREG(statbuf.st_mode)) {
                // For directories always allow.
                ret = writeResponse(response, 0);
            } else {
                // It is a file. Unignore it.
                ret = fanotify_mark(fd, FAN_MARK_REMOVE |
                                    FAN_MARK_IGNORED_MASK, FAN_MODIFY, metadata->fd,
                                    NULL);
                if (ret == -1 && errno != ENOENT) {
                    std::stringstream msg;
                    char errbuf[256];
                    msg << "Failure to unignore file: "
                        << strerror_r(errno, errbuf, sizeof (errbuf));
                    Messaging::message(Messaging::ERROR, msg.str());
                }
                response.response = e->getScanCache()->get(&statbuf);
                if (response.response == ScanCache::CACHE_MISS) {
                    struct ScanTask *task;
                    task = (struct ScanTask *) malloc(sizeof (struct ScanTask));
                    if (task == NULL) {
                        Messaging::message(Messaging::ERROR, "Out of memory\n");
                        response.fd = metadata->fd;
                        response.response = FAN_ALLOW;
                        writeResponse(response, 0);
                    } else {
                        tobeclosed = 0;
                        task->metadata = *metadata;
                        task->fp = this;
                        tp->add((void *) task);
                    }
                } else {
                    writeResponse(response, 0);
                }
            }
        } // FAN_OPEN_PERM
    } // ret = fstat
    if (tobeclosed) {
        close(metadata->fd);
    }

    fflush(stdout);
}

/**
 * @brief Handle fanotify events.
 *
 * @param buf buffer with events
 * @param len length of the buffer
 */
void FanotifyPolling::handleFanotifyEvents(const void *buf, int len) {
    const struct fanotify_event_metadata *metadata =
        (const struct fanotify_event_metadata *) buf;

    while (FAN_EVENT_OK(metadata, len)) {
        if (metadata->fd == FAN_NOFD) {
            Messaging::message(Messaging::ERROR,
                               "Received FAN_NOFD from fanotiy.");
        } else {
            handleFanotifyEvent(metadata);
        }
        metadata = FAN_EVENT_NEXT(metadata, len);
    }
    return;
}

/**
 * @brief Starts polling fanotify events.
 * @param env environment
 * @return success
 */
FanotifyPolling::FanotifyPolling(Environment * env) {
    int ret;
    struct timespec waiting_time_rem;
    struct timespec waiting_time_req;
    char errbuf[256];

    e = env;

    status = INITIAL;

    try {
        virusScan = new VirusScan(e);
    } catch (enum VirusScan::Status e) {
        Messaging::message(Messaging::ERROR, "Loading database failed.\n");
        throw FAILURE;
    }

    ret = pthread_mutex_init(&mutex_response, NULL);
    if (ret != 0) {
        std::stringstream msg;
        msg << "Failure to intialize mutex: "
            << strerror_r(errno, errbuf, sizeof (errbuf));
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
        msg << "Failure to create thread: "
            << strerror_r(errno, errbuf, sizeof (errbuf));
        Messaging::message(Messaging::ERROR, msg.str());
        throw FAILURE;
    }
    ret = pthread_setname_np(thread, "skyldav-f");
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
 */
FanotifyPolling::~FanotifyPolling() {
    void *result;
    int ret;
    char errbuf[256];

    if (status != RUNNING) {
        Messaging::message(Messaging::ERROR, "Polling not started.\n");
        return;
    }

    // Stop the mount polling thread.
    if (mp) {
        delete mp;
    }

    // Stop the fanotify polling thread.
    status = STOPPING;
    ret = (int) pthread_join(thread, &result);
    if (ret != 0) {
        std::stringstream msg;
        msg << "Failure to join thread: "
            << strerror_r(errno, errbuf, sizeof (errbuf));
        Messaging::message(Messaging::ERROR, msg.str());
    } else if (status != SUCCESS) {
        Messaging::message(Messaging::ERROR,
                           "Ending thread signals failure.\n");
    }

    // Close the fanotify file descriptor.
    fanotifyClose();

    // Delete thread pool.
    delete tp;

    // Destroy the mutex.
    if (pthread_mutex_destroy(&mutex_response)) {
        std::stringstream msg;
        msg << "Failure destroying thread: "
            << strerror_r(errno, errbuf, sizeof (errbuf));
        Messaging::message(Messaging::ERROR, msg.str());
    }

    // Unload the virus scanner.
    try {
        delete virusScan;
    } catch (enum VirusScan::Status e) {
        Messaging::message(Messaging::ERROR,
                           "Failure unloading virus scanner\n");
    }
}

/**
 * @brief Writes fanotify response
 * @param response response
 * @param doBuffer if != 0 write to buffer
 * @return success = 0
 */
int FanotifyPolling::writeResponse(const struct fanotify_response response,
                                   int doBuffer) {
    int ret = 0;
    struct stat statbuf;

    pthread_mutex_lock(&mutex_response);

    if (doBuffer) {
        // Add file to scan buffer.
        ret = fstat(response.fd, &statbuf);
        if (ret != -1) {
            e->getScanCache()->add(&statbuf, response.response);
        }
    }

    if (response.response == FAN_DENY && response.fd >= FAN_NOFD) {
        char path[PATH_MAX];
        int path_len;
        sprintf(path, "/proc/self/fd/%d", response.fd);
        path_len = readlink(path, path, sizeof (path) - 1);
        if (path_len > 0) {
            path[path_len] = '\0';
            std::stringstream msg;
            msg << "Access to file \"" << path << "\" denied.";
            Messaging::message(Messaging::WARNING, msg.str());
        }
    }

    ret = write(fd, &response, sizeof (struct fanotify_response));
    if (ret == -1 && status == RUNNING && errno != ENOENT) {
        std::stringstream msg;
        char errbuf[256];
        fprintf(stderr, "Failure to write response %u: %s\n",
                response.response,
                strerror_r(errno, errbuf, sizeof (errbuf)));
        msg << "Failure to write response: "
            << strerror_r(errno, errbuf, sizeof (errbuf));
        Messaging::message(Messaging::ERROR, msg.str());
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
        char errbuf[256];
        msg << "fanotifyOpen: "
            << strerror_r(errno, errbuf, sizeof (errbuf));
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
        char errbuf[256];
        status = FAILURE;
        std::stringstream msg;
        msg << "fanotifyClose: " << strerror_r(errno, errbuf, sizeof (errbuf));
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
    uint64_t mask = FAN_OPEN_PERM | FAN_MODIFY | FAN_CLOSE_WRITE;
    int dfd = AT_FDCWD;
    int ret;

    ret = fanotify_mark(fd, flags, mask, dfd, mount);
    if (ret != 0) {
        std::stringstream msg;
        char errbuf[256];
        msg << "Failure to set mark on '" << mount << "': "
            << strerror_r(errno, errbuf, sizeof (errbuf));
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
    uint64_t mask = FAN_OPEN_PERM | FAN_MODIFY | FAN_CLOSE_WRITE;
    int dfd = AT_FDCWD;
    int ret;

    ret = fanotify_mark(fd, flags, mask, dfd, mount);
    if (ret != 0 && errno != ENOENT) {
        std::stringstream msg;
        char errbuf[256];
        msg << "Failure to remove mark from '"
            << mount << "': " << strerror_r(errno, errbuf, sizeof (errbuf));
        Messaging::message(Messaging::ERROR, msg.str());
        return EXIT_FAILURE;
    }
    std::stringstream msg;
    msg << "Stopped watching: " << mount;
    Messaging::message(Messaging::DEBUG, msg.str());
    return EXIT_SUCCESS;
}

