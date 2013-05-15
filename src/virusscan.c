/* 
 * File:   virusscan.c
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

#include <clamav.h>
#include <limits.h>
#include <stdio.h>
#include <syslog.h>
#include "virusscan.h"

/**
 * @brief Reference to virus scan engine.
 */
static struct cl_engine *engine;

/**
 * @brief Writes log entry.
 *
 * @param fd file descriptor
 * @param virname name of virus
 */
static void writelog(const int fd, const char *virname) {
    int path_len;
    char path[PATH_MAX+1];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    path_len = readlink(path, path, sizeof (path) - 1);
    if (path_len < 0) {
        path_len = 0;
    }
    path[path_len] = '\0';
    syslog(LOG_CRIT, "Virus \"%s\" detected in file \"%s\".", virname, path);
}

/**
 * @brief Initializes virus scan engine.
 *
 * @return success
 */
int skyld_scaninit() {
    int ret;
    unsigned int sigs;

    ret = cl_init(CL_INIT_DEFAULT);
    if (ret != CL_SUCCESS) {
        printf("cl_init() error: %s\n", cl_strerror(ret));
        return SKYLD_SCANERROR;
    }
    engine = cl_engine_new();
    if (engine == NULL) {
        printf("Can't create new engine\n");
        return SKYLD_SCANERROR;
    }
    // sigs must be zero before calling cl_load.
    sigs = 0;
    ret = cl_load(cl_retdbdir(), engine, &sigs, CL_DB_STDOPT);
    if (ret != CL_SUCCESS) {
        printf("cl_retdbdir error: %s\n", cl_strerror(ret));
        cl_engine_free(engine);
        return SKYLD_SCANERROR;
    } else {
        printf("%u signatures loaded\n", sigs);
    }
    if ((ret = cl_engine_compile(engine)) != CL_SUCCESS) {
        printf("cl_engine_compile() error: %s\n", cl_strerror(ret));
        cl_engine_free(engine);
        return SKYLD_SCANERROR;
    }
    return SKYLD_SCANOK;
}

/**
 * @brief Scans file for virus.
 *
 * @return success
 */
int skyld_scan(const int fd) {
    int success = SKYLD_SCANOK;
    int ret;
    const char *virname;
    ret = cl_scandesc(fd, &virname, NULL, engine, CL_SCAN_STDOPT);
    if (ret == CL_VIRUS) {
        printf("Virus detected: %s\n", virname);
        writelog(fd, virname);
        success = SKYLD_SCANVIRUS;
    } else {
        if (ret != CL_CLEAN)
            printf("Error: %s\n", cl_strerror(ret));
    }
    return success;
}

/**
 * @brief Finalizes the virus scan engine.
 *
 * @return success
 */
int skyld_scanfinalize() {
    int ret;
    ret = cl_engine_free(engine);
    if (ret != CL_SUCCESS) {
        return SKYLD_SCANERROR;
    }
    return SKYLD_SCANOK;
}
