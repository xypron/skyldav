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
 * @file MountPolling.cc
 * @brief Poll /proc/mounts to detect mount events.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE // enable ppoll
#endif // _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L // enable nanosleep
#include <errno.h>
#include <features.h>
#include <fcntl.h>
#include <iostream>
#include <poll.h>
#include <pthread.h>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "Environment.h"
#include "FanotifyPolling.h"
#include "listmounts.h"
#include "Messaging.h"
#include "MountPolling.h"

/**
 * @brief thread.
 */
static pthread_t thread;

/**
 * @brief Thread listening to mount events.
 * 
 * @param ccbptr pointer to callback routine
 * @return pointer to int indicating success
 */
void * MountPolling::run(void *obj) {
    MountPolling *mp = (MountPolling *) obj;
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
    /*
     * number of structures with nonzero revents fields, 0 = timeout
     */
    int ret;

    mp->status = INITIAL;

    // Open file /proc/mounts.
    mfd = open("/proc/mounts", O_RDONLY, 0);
    if (mfd < 0) {
        std::stringstream msg;
        msg << "Failure to open /proc/mounts: "
                << strerror(errno);
        Messaging::message(Messaging::ERROR, msg.str());

        mp->status = FAILURE;
        return NULL;
    }
    fds.fd = mfd;
    fds.events = POLLERR | POLLPRI;
    fds.revents = 0;
    mp->status = RUNNING;
    while (mp->status == RUNNING) {
        ret = poll(&fds, nfds, 1);
        if (ret > 0) {
            if (fds.revents & POLLERR) {
                mp->callback();
            }
            fds.revents = 0;
        } else if (ret < 0) {
            if (errno != EINTR) {
                std::stringstream msg;
                msg << "Failure to poll /proc/mounts: "
                        << strerror(errno);
                Messaging::message(Messaging::ERROR, msg.str());
                close(mfd);
                mp->status = FAILURE;
                return NULL;
            }
        }
    }
    close(mfd);
    mp->status = SUCCESS;
    return NULL;
}

/**
 * @brief Tracks mountevents.
 */
void MountPolling::callback() {
    const char *dir;
    const char *type;
    StringSet *cbmounts;
    StringSet::iterator pos;
    std::string *str;

    cbmounts = new StringSet();

    do {
        if (listmountinit()) {
            break;
        }
        while (!listmountnext(&dir, &type)) {
            if (!isFuse(type)
                    && !nomarkfs->find(type)
                    && !nomarkmnt->find(dir)) {
                cbmounts->add(dir);
            }
        }
    } while (0);

    for (pos = cbmounts->begin(); pos != cbmounts->end(); pos++) {
        if (0 == mounts->count(*pos)) {
            str = *pos;
            FanotifyPolling::markMount(fd, str->c_str());
        }
    }
    for (pos = mounts->begin(); pos != mounts->end(); pos++) {
        if (0 == cbmounts->count(*pos)) {
            str = *pos;
            FanotifyPolling::unmarkMount(fd, str->c_str());
        }
    }

    delete(mounts);
    mounts = cbmounts;

    listmountfinalize();
}

/**
 * @brief Checks if a mount is using a filesystem in userspace (fuse).
 * @param type mount type
 * @return 1 if mount type is "fuse" or starts with "fuse.".
 */
int MountPolling::isFuse(const char *type) {
    int ret = 0;
    if (type[0] == 'f'
            && type[1] == 'u'
            && type[2] == 's'
            && type[3] == 'e'
            && (type[4] == '.' || type[4] == '\0')) {
        ret = 1;
    }
    return ret;
}

/**
 * Creates new mount polling object.
 * 
 * @param nomarkfs
 * @param nomarkmnt
 */
MountPolling::MountPolling(int ffd, Environment *env) {
    pthread_attr_t attr;
    int ret;
    struct timespec waiting_time_rem;
    struct timespec waiting_time_req;

    fd = ffd;
    this->nomarkfs = env->getNoMarkFileSystems();
    this->nomarkmnt = env->getNoMarkMounts();

    status = INITIAL;

    this->mounts = new StringSet();
    if (this->mounts == NULL) {
        throw FAILURE;
    }

    MountPolling::callback();

    ret = pthread_attr_init(&attr);
    if (ret != 0) {
        std::stringstream msg;
        msg << "Failure to set thread attributes: " << strerror(ret);
        Messaging::message(Messaging::ERROR, msg.str());
        throw FAILURE;
    }
    ret = pthread_create(&thread, &attr, run, (void *) this);
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
}

/**
 * @brief Deletes mount polling object.
 */
MountPolling::~MountPolling() {
    void *result;
    int ret;
    StringSet::iterator pos;
    std::string *str;

    if (status != RUNNING) {
        Messaging::message(Messaging::ERROR, "Polling not started.\n");
        throw FAILURE;
    }

    // Ask polling thread to stop.
    status = STOPPING;

    // Unmark all mounts.
    if (mounts != NULL) {
        for (pos = mounts->begin(); pos != mounts->end(); pos++) {
            str = *pos;
            FanotifyPolling::unmarkMount(fd, str->c_str());
        }
        delete(MountPolling::mounts);
        MountPolling::mounts = NULL;
    }

    // Wait for thread to stop.
    ret = (int) pthread_join(thread, &result);
    if (ret != 0) {
        std::stringstream msg;
        msg << "Failure to join thread: " << strerror(ret);
        Messaging::message(Messaging::ERROR, msg.str());
        throw FAILURE;
    }
    if (status != SUCCESS) {
        Messaging::message(Messaging::ERROR, 
                "Ending thread signals failure.\n");
        throw FAILURE;
    }
}
