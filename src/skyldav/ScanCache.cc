/* 
 * File:   ScanCache.h
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
 * @file ScanCache.h
 * @brief Cache for virus scanning results.
 */
#include "ScanCache.h"
#include <time.h>

ScanCache::ScanCache() {
}

/**
 * @brief Adds scan result to cache.
 * @param stat File status as returned by fstat()
 * @param response Response to be used for fanotify (FAN_ALLOW, FAN_DENY)
 */
void ScanCache::add(const struct stat *stat, const int response) {
    ScanCache::iterator it;
    ScanResult *scr = new ScanResult();
    scr->dev = stat->st_dev;
    scr->ino = stat->st_ino;
    scr->mtime = stat->st_mtime;
    scr->response = response;
    gmtime(&(scr->age));

    it = find(scr);
    if (it != ScanCache::end()) {
        erase(it);
    }
    if (!this->insert(scr).second) {
        delete scr;
    }
}

/**
 * @brief Adds scan result to cache.
 * @param stat file status as returned by fstat()
 * @return response to be used for fanotify (FAN_ALLOW, FAN_DENY) or -1
 */
int ScanCache::get(const struct stat *stat) {
    ScanCache::iterator it;
    ScanResult *scr = new ScanResult();
    scr->dev = stat->st_dev;
    scr->ino = stat->st_ino;

    it = find(scr);
    delete scr;
    if (it == ScanCache::end()) {
        return -1;
    }
    scr = *it;
    return scr->response;
}

/**
 * @brief Adds scan result to cache.
 * @param stat file status as returned by fstat()
 */
void ScanCache::remove(const struct stat *stat) {
    ScanCache::iterator it;
    ScanResult *scr = new ScanResult();
    scr->dev = stat->st_dev;
    scr->ino = stat->st_ino;

    it = find(scr);
    if (it != ScanCache::end()) {
        delete *it;
        erase(it);
    }
    delete scr;
}

ScanCache::~ScanCache() {
    ScanCache::iterator pos;
    for (pos = begin(); pos != end(); pos++) {
        delete *pos;
    }
    this->clear();
}

