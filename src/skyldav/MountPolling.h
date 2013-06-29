/* 
 * File:   MountPolling.h
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
 */

/**
 * @file MountPolling.h
 * @brief Poll /proc/mounts to detect mount events.
 */
#ifndef POLLMOUNTS_H
#define	POLLMOUNTS_H

#include <signal.h>
#include "StringSet.h"

#ifdef	__cplusplus
extern "C" {
#endif

    /**
     * @brief Polls mount and unmout events
     */
    class MountPolling {
    public:

        enum Status {
            INITIAL = 0,
            RUNNING = 1,
            STOPPING = 2,
            FAILURE = 3,
            SUCCESS = 4
        };

        /**
         * Pointer to callback function for polling mounts.
         */
        typedef void (*callbackptr)();
        MountPolling(int ffd, Environment *);
        ~MountPolling();
    private:
        /**
         * @brief fanotify file descriptor
         */
        int fd;
        void callback();
        /**
         * @brief Mounts
         */
        StringSet *mounts;
        /**
         * @brief File systems that shall not be tracked.
         */
        StringSet *nomarkfs;
        /**
         * @brief Mount points that shall not be tracked.
         */
        StringSet *nomarkmnt;
        static void *run(void *);
        /**
         * @brief Status of thread.
         */
        sig_atomic_t status;
    };


#ifdef	__cplusplus
}
#endif

#endif	/* POLLMOUNTS_H */

