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
#include <limits.h>
#include <sstream>
#include <stdio.h>
#include <syslog.h>
#include "unistd.h"
#include "VirusScan.h"
#include "Messaging.h"

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
 * @brief Initializes virus scan engine.
 */
VirusScan::VirusScan() {
    int ret;
    unsigned int sigs;

    ret = cl_init(CL_INIT_DEFAULT);
    if (ret != CL_SUCCESS) {
        std::stringstream msg;
        msg << "cl_init() error: " << cl_strerror(ret);
        Messaging::message(Messaging::ERROR, msg.str());
        throw SCANERROR;
    }
    engine = cl_engine_new();
    if (engine == NULL) {
        Messaging::message(Messaging::ERROR,
                "Can't create new viurs scan engine.");
        throw SCANERROR;
    }
    // sigs must be zero before calling cl_load.
    sigs = 0;
    ret = cl_load(cl_retdbdir(), engine, &sigs, CL_DB_STDOPT);
    if (ret != CL_SUCCESS) {
        std::stringstream msg;
        msg << "cl_retdbdir() error: " << cl_strerror(ret);
        Messaging::message(Messaging::ERROR, msg.str());
        cl_engine_free(engine);
        throw SCANERROR;
    } else {
        std::stringstream msg;
        msg << sigs << "  signatures loaded\n";
        Messaging::message(Messaging::DEBUG, msg.str());
    }
    if ((ret = cl_engine_compile(engine)) != CL_SUCCESS) {
        std::stringstream msg;
        msg << "cl_engine_compile() error: " << cl_strerror(ret);
        Messaging::message(Messaging::ERROR, msg.str());
        cl_engine_free(engine);
        throw SCANERROR;
    }
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

    ret = cl_scandesc(fd, &virname, NULL, engine, CL_SCAN_STDOPT);
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
    return success;
}

/**
 * @brief Checks if database has changed.
 * @returned 0 = unchanged, 1 = changed
 */
int VirusScan::dbstat_check() {
    int ret = 0;
	if(cl_statchkdir(&dbstat) == 1) {
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
 * @brief Deletes the virus scanner.
 */
VirusScan::~VirusScan() {
    int ret;
    ret = cl_engine_free(engine);
    if (ret != 0) {
        std::stringstream msg;
        msg << "cl_engine_free() error: " << cl_strerror(ret);
        Messaging::message(Messaging::ERROR, msg.str());
        throw SCANERROR;
    }
}
