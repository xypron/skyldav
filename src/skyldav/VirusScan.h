/*
 * File:   virusscan.h
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
 * @file VirusScan.h
 * @brief Scans files for viruses.
 */
#ifndef VIRUSSCAN_H
#define	VIRUSSCAN_H

#include <clamav.h>
#include <pthread.h>
#include "Environment.h"

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * @brief Scans files for viruses.
 */

class VirusScan {
public:

    /**
     * @brief Status of virus scanning.
     */
    enum Status {
        /**
         * @brief OK.
         */
        SCANOK = 0,
        /**
         * @brief An error occured.
         */
        SCANERROR = -1,
        /**
         * @brief A virus was found.
         */
        SCANVIRUS = 1
    };

    enum RunStatus {
        RUNNING,
        STOPPING,
        STOPPED,
    };

    VirusScan(Environment *);
    int scan(const int fd);
    ~VirusScan();
private:
    /**
     * @brief environment
     */
    Environment * env;
    /**
     * @brief Struture indicating if database has changed.
     */
    struct cl_stat dbstat;
    /**
     * @brief Reference to virus scan engine.
     */
    struct cl_engine *engine;
    /**
     * @brief Mutex for accessing the engine.
     */
    pthread_mutex_t mutexEngine;
    /**
     * @brief Mutex for accessing the engine.
     */
    pthread_mutex_t mutexUpdate;
    /**
     * Run status
     */
    enum RunStatus status;
    /**
     * @brief Thrad for updating
     */
    pthread_t updateThread;
    /**
     * @brief Reference count of virus scan enginge.
     */
    int engineRefCount;

    struct cl_engine *createEngine();
    int createThread();
    void dbstat_clear();
    int dbstat_check();
    void dbstat_free();
    void destroyEngine(cl_engine *);
    struct cl_engine *getEngine();
    void releaseEngine();
    void log_virus_found(const int fd, const char *virname);
    static void *updater(void *);
};
#ifdef	__cplusplus
}
#endif

#endif	/* VIRUSSCAN_H */
