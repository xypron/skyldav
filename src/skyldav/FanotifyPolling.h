/* 
 * File:   FanotifyPolling.h
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
 * @file FanotifyPolling.h
 * @brief Poll fanotify events.
 */

#ifndef POLLFANOTIFY_H
#define	POLLFANOTIFY_H

#include <sys/fanotify.h>
#include <pthread.h>
#include "Environment.h"
#include "MountPolling.h"
#include "StringSet.h"
#include "ThreadPool.h"
#include "VirusScan.h"

#ifdef	__cplusplus
extern "C" {
#endif

    /**
     * @brief Polls fanotify events.
     */
    class FanotifyPolling {
    public:

        enum Status {
            INITIAL = 0,
            RUNNING = 1,
            STOPPING = 2,
            FAILURE = 3,
            SUCCESS = 4
        };

        FanotifyPolling(Environment *);
        ~FanotifyPolling();
        static int markMount(int fd, const char *mount);
        static int unmarkMount(int fd, const char *mount);
    private:
        /**
         * @brief Environment
         */
        Environment *e;
        /**
         * @brief Fanotify file descriptor.
         */
        int fd;
        /**
         * @brief Worker thread.
         */
        pthread_t thread;
        /**
         * @brief Mount polling object.
         */
        MountPolling *mp;
        /**
         * @brief Thread pool for scanning tasks.
         */
        ThreadPool *tp;
        /**
         * @brief Mutex for fanotify response.
         */
        pthread_mutex_t mutex_response;
        /**
         * @brief Status of fanotify polling object.
         */
        enum Status status;
        /**
         * Virus scanner.
         */
        VirusScan *virusScan;

        /**
         * @brief Scan task.
         */
        struct ScanTask {
            /**
             * @brief fanotify polling object
             */
            FanotifyPolling *fp;
            /**
             * @brief fanotify metadata
             */
            struct fanotify_event_metadata metadata;
        };

        typedef void (*skyld_pollfanotifycallbackptr)(const int fd,
                const void *buf, int len);

        static void *run(void *);
        static void *scanFile(void *workitem);
        void handleFanotifyEvents(const void *buf, int len);
        void handleFanotifyEvent(const struct fanotify_event_metadata *);
        
        
        int writeResponse(const struct fanotify_response, int);
        int fanotifyOpen();
        int fanotifyClose();
    };

#ifdef	__cplusplus
}
#endif

#endif	/* POLLFANOTIFY_H */
