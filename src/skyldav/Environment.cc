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

Environment::Environment() {
    nomarkfs = new StringSet();
    nomarkmnt = new StringSet();
    localfs = new StringSet();
    scache = new ScanCache(this);
    nThreads = 4;
    cacheMaxSize = 10000;
}

StringSet *Environment::getNoMarkFileSystems() {
    return nomarkfs;
}

StringSet *Environment::getNoMarkMounts() {
    return nomarkmnt;
}

StringSet *Environment::getLocalFileSystems() {
    return localfs;
}

unsigned int Environment::getCacheMaxSize() {
    return cacheMaxSize;
}

ScanCache *Environment::getScanCache() {
    return scache;
}

int Environment::getNumberOfThreads() {
    return nThreads;
}

void Environment::setNumberOfThreads(int n) {
    nThreads = n;
}

Environment::~Environment() {
    delete nomarkfs;
    delete nomarkmnt;
    delete localfs;
    delete scache;
}

