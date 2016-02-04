/*
 * File:   Environment.cc
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
 * @file Environment.cc
 * @brief Envronment.
 */
#include "Environment.h"

/**
 * @brief Creates a new environment.
 */
Environment::Environment() {
    excludepath = new StringSet();
    localfs = new StringSet();
    nomarkfs = new StringSet();
    nomarkmnt = new StringSet();
    scache = new ScanCache(this);
    nThreads = 4;
    cacheMaxSize = 10000;
    cleanCacheOnUpdate = 1;
}

/**
 * @brief Determines if cache shall be cleaned when the virus scanner
 * receives a new pattern file.
 *
 * @return cache shall be cleaned on update
 */
int Environment::isCleanCacheOnUpdate() {
    return cleanCacheOnUpdate;
}

/**
 * @brief Gets the set of paths that shall not be scanned.
 *
 * @return paths no to be scanned
 */
StringSet *Environment::getExcludePaths() {
    return excludepath;
}

/**
 * @brief Gets the list of file systems that shall not be scanned.
 *
 * @return file systems not to be scanned.
 */
StringSet *Environment::getNoMarkFileSystems() {
    return nomarkfs;
}

/**
 * @brief Gets the list of mounts not to be scanned.
 *
 * @return mounts not to be scanned
 */
StringSet *Environment::getNoMarkMounts() {
    return nomarkmnt;
}

/**
 * @brief Gets the list of file systems considered local.
 * This list can be used to decide if scan results shall be cached.
 *
 * @return list of file systems considered local
 */
StringSet *Environment::getLocalFileSystems() {
    return localfs;
}

/**
 * @brief Gets the maximum number of entries in the cache with scan results.
 *
 * @return maximum cache size
 */
unsigned int Environment::getCacheMaxSize() {
    return cacheMaxSize;
}

/**
 * @brief Sets the maximum number of entries in the cache with scan results.
 *
 * @param size maximum cache size
 */
void Environment::setCacheMaxSize(unsigned int size) {
    cacheMaxSize = size;
}

/**
 * @brief Gets the scan cache.
 *
 * @return scan cache
 */
ScanCache *Environment::getScanCache() {
    return scache;
}

/**
 * @brief Gets the number of threads used to call the virus scanner.
 *
 * @return number of threads
 */
int Environment::getNumberOfThreads() {
    return nThreads;
}

/**
 * @brief Sets if cache shall be cleaned when the virus scanner receives a new
 * pattern file.
 *
 * @param value cache shall be cleaned on update
 */
void Environment::setCleanCacheOnUpdate(int value) {
    cleanCacheOnUpdate = value;
}

/**
 * @brief sets the number of threads used to call the virus scanner.
 *
 * @param n number of threads
 */
void Environment::setNumberOfThreads(int n) {
    nThreads = n;
}

/**
 * @brief Destroys the environment.
 */
Environment::~Environment() {
    delete localfs;
    delete excludepath;
    delete nomarkfs;
    delete nomarkmnt;
    delete scache;
}
