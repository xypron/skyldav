/* 
 * File:   virusscan.c
 * 
 * Copyright 2013 Heinrich Schuchardt <xypron.glpk@gmx.de>
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
 * @file VirusScan.cc
 * @brief Scans files for viruses.
 */
#include <cstring>
#include <ctime>
#include <limits.h>
#include <signal.h>
#include <sstream>
#include <stdio.h>
#include <syslog.h>
#include "unistd.h"
#include "VirusScan.h"
#include "Messaging.h"

/**
 * @brief Initializes virus scan engine.
 */
VirusScan::VirusScan(Environment * e) {
    int ret;

    env = e;
    status = RUNNING;
    engineRefCount = 0;
    pthread_mutex_init(&mutexEngine, NULL);
    pthread_mutex_init(&mutexUpdate, NULL);

    ret = cl_init(CL_INIT_DEFAULT);
    if (ret != CL_SUCCESS) {
        std::stringstream msg;
        msg << "cl_init() error: " << cl_strerror(ret);
        Messaging::message(Messaging::ERROR, msg.str());
        throw SCANERROR;
    }

    // Create virus scan engine.
    engine = createEngine();
    // Initialize monitoring of pattern update.
    dbstat_clear();

    if (createThread()) {
        Messaging::message(Messaging::ERROR, "Cannot create thread.");
        cl_engine_free(engine);
        throw SCANERROR;
    }
}

/**
 * @brief Creates a new virus scan engine.
 * 
 * @return virus scan engine
 */
struct cl_engine *VirusScan::createEngine() {
    int ret;
    unsigned int sigs;
    cl_engine *e;

    Messaging::message(Messaging::DEBUG, "Loading virus database");
    e = cl_engine_new();
    if (e == NULL) {
        Messaging::message(Messaging::ERROR,
                "Can't create new virus scan engine.");
        throw SCANERROR;
    }
    // sigs must be zero before calling cl_load.
    sigs = 0;
    ret = cl_load(cl_retdbdir(), e, &sigs, CL_DB_STDOPT);
    if (ret != CL_SUCCESS) {
        std::stringstream msg;
        msg << "cl_retdbdir() error: " << cl_strerror(ret);
        Messaging::message(Messaging::ERROR, msg.str());
        cl_engine_free(e);
        throw SCANERROR;
    } else {
        std::stringstream msg;
        msg << sigs << "  signatures loaded";
        Messaging::message(Messaging::DEBUG, msg.str());
    }
    if ((ret = cl_engine_compile(e)) != CL_SUCCESS) {
        std::stringstream msg;
        msg << "cl_engine_compile() error: " << cl_strerror(ret);
        Messaging::message(Messaging::ERROR, msg.str());
        cl_engine_free(e);
        throw SCANERROR;
    }
    {
        int err;
        time_t db_time;
        struct tm *timeinfo;
        uint version;
        std::stringstream msg;
        char buffer[80];

        do {
            version = (uint) cl_engine_get_num(e, CL_ENGINE_DB_VERSION, &err);
            if (err != CL_SUCCESS) {
                break;
            }
            db_time = (time_t) cl_engine_get_num(e, CL_ENGINE_DB_TIME, &err);
            if (err != CL_SUCCESS) {
                break;
            }
            timeinfo = gmtime(&db_time);
            strftime(buffer, sizeof (buffer), "%F %T UTC", timeinfo);
            msg << "ClamAV database version " << version << ", " << buffer;
            Messaging::message(Messaging::INFORMATION, msg.str());
        } while (0);
    }
    return e;
}

/**
 * Destroys virus scan engine.
 * @param e virus scan engine
 */
void VirusScan::destroyEngine(cl_engine * e) {
    int ret;
    ret = cl_engine_free(e);
    if (ret != 0) {
        std::stringstream msg;
        msg << "cl_engine_free() error: " << cl_strerror(ret);
        Messaging::message(Messaging::ERROR, msg.str());
        throw SCANERROR;
    }
}

/**
 * @brief Gets reference to virus scan engine.
 * 
 * @return scan engine
 */
struct cl_engine * VirusScan::getEngine() {
    struct cl_engine *ret = NULL;

    // Wait for update to complete
    pthread_mutex_lock(&mutexUpdate);
    pthread_mutex_unlock(&mutexUpdate);

    pthread_mutex_lock(&mutexEngine);
    ret = engine;
    engineRefCount++;
    pthread_mutex_unlock(&mutexEngine);
    return ret;
}

/**
 * @brief Creates a new thread for managing the scan engine.
 * 
 * @return success = 0
 */
int VirusScan::createThread() {
    int ret;

    if (pthread_create(&updateThread, NULL, updater, this)) {
        ret = 1;
    } else {
        ret = 0;
    }
    return ret;
}

/**
 * @brief Checks if database has changed.
 * @returned 0 = unchanged, 1 = changed
 */
int VirusScan::dbstat_check() {
    int ret = 0;
    if (cl_statchkdir(&dbstat) == 1) {
        ret = 1;
        cl_statfree(&dbstat);
        cl_statinidir(cl_retdbdir(), &dbstat);
    }
    return ret;
}

/**
 * @brief Clears database status.
 */
void VirusScan::dbstat_clear() {
    memset(&dbstat, 0, sizeof (struct cl_stat));
    cl_statinidir(cl_retdbdir(), &dbstat);
}

/**
 * @brief Frees database status.
 */
void VirusScan::dbstat_free() {
    cl_statfree(&dbstat);
}

/**
 * @brief Writes log entry.
 *
 * @param fd file descriptor
 * @param virname name of virus
 */
void VirusScan::log_virus_found(const int fd, const char *virname) {
    int path_len;
    char path[PATH_MAX + 1];
    std::stringstream msg;

    snprintf(path, sizeof (path), "/proc/self/fd/%d", fd);
    path_len = readlink(path, path, sizeof (path) - 1);
    if (path_len < 0) {
        path_len = 0;
    }
    path[path_len] = '\0';
    msg << "Virus \"" << virname << "\" detected in file \"" << path << "\".";
    Messaging::message(Messaging::ERROR, msg.str());
}

/**
 * Decreases the viurs engine reference count.
 */
void VirusScan::releaseEngine() {
    pthread_mutex_lock(&mutexEngine);
    engineRefCount--;
    pthread_mutex_unlock(&mutexEngine);
}

/**
 * @brief Scans file for virus.
 *
 * @return success
 */
int VirusScan::scan(const int fd) {
    int success = SCANOK;
    int ret;
    const char *virname;

    ret = cl_scandesc(fd, &virname, NULL, getEngine(), CL_SCAN_STDOPT);
    switch (ret) {
        case CL_CLEAN:
            success = SCANOK;
            break;
        case CL_VIRUS:
            log_virus_found(fd, virname);
            success = SCANVIRUS;
            break;
        default:
            std::stringstream msg;
            msg << "cl_scandesc() error: " << cl_strerror(ret);
            Messaging::message(Messaging::ERROR, msg.str());
            success = SCANOK;
            break;
    }
    releaseEngine();
    return success;
}

/**
 * @brief Thread to update engine.
 * 
 * @param threadPool thread pool
 * @return return value
 */
void * VirusScan::updater(void *virusScan) {
    int count = 0;
    cl_engine *e;
    struct timespec interval = {
        1,
        0
    };
    struct timespec interval2 = {
        0,
        100000
    };
    VirusScan *vs;

    vs = (VirusScan *) virusScan;

    for (;;) {
        if (vs->status == STOPPING) {
            break;
        }
        nanosleep(&interval, NULL);
        count++;
        // Every minute check for virus database updates
        if (count >= 60) {
            if (vs->dbstat_check()) {
                Messaging::message(Messaging::INFORMATION,
                        "ClamAV database update detected.");
                try {
                    // Create the new engine.
                    e = vs->createEngine();
                    // Stop scanning.
                    pthread_mutex_lock(&(vs->mutexUpdate));
                    // Wait for all running scans to be finished.
                    for (;;) {
                        pthread_mutex_lock(&(vs->mutexEngine));
                        if (vs->engineRefCount == 0) {
                            break;
                        }
                        pthread_mutex_unlock(&(vs->mutexEngine));
                        nanosleep(&interval2, NULL);
                    }
                    // Destroy the old engine
                    vs->destroyEngine(vs->engine);
                    vs->engine = e;
                    vs->env->getScanCache()->clear();
                    pthread_mutex_unlock(&(vs->mutexEngine));
                    Messaging::message(Messaging::INFORMATION,
                            "Using updated ClamAV database.");
                } catch (Status e) {
                }
                // Allow scanning.
                pthread_mutex_unlock(&(vs->mutexUpdate));
            }
        }
    }
    vs->status = STOPPED;
    return NULL;
}

/**
 * @brief Deletes the virus scanner.
 */
VirusScan::~VirusScan() {
    struct timespec interval = {
        0,
        1000000
    };

    status = STOPPING;
    do {
        nanosleep(&interval, NULL);
    } while (status == STOPPING);

    destroyEngine(engine);
    pthread_mutex_destroy(&mutexUpdate);
    pthread_mutex_destroy(&mutexEngine);
    dbstat_free();
}
