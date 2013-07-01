/* 
 * File:   Environment.h
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
 *
 */

/**
 * @file Environment.h
 * @brief Envronment.
 */
#ifndef ENVIRONMENT_H
#define	ENVIRONMENT_H

#include "ScanCache.h"
#include "StringSet.h"

class ScanCache;

/**
 * @brief The environment holds variables that are shared by instances of
 * multiple classes.
 */

class Environment {
public:
    Environment();
    StringSet *getNoMarkFileSystems();
    StringSet *getNoMarkMounts();
    StringSet *getLocalFileSystems();
    int getCacheMaxSize();
    ScanCache *getScanCache();
    int getNumberOfThreads();
    void setNumberOfThreads(int);
    virtual ~Environment();
private:
    /**
     * @brief File systems which shall not be scanned.
     */
    StringSet *nomarkfs;
    /**
     * @brief Mounts that shall not be scanned.
     */
    StringSet *nomarkmnt;
    /**
     * @brief File systems for local drives.
     */
    StringSet *localfs;
    /**
     * @brief Number of threads for virus scanning.
     */
    int nThreads;
    /**
     * @brief Cache for scan results.
     */
    ScanCache *scache;
    /**
     * @brief Maximum cache size.
     */
    int cacheMaxSize;
};

#endif	/* ENVIRONMENT_H */

