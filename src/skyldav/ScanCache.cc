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
#include <iostream>
#include <sstream>
#include <time.h>
#include "Messaging.h"
#include "ScanCache.h"

ScanCache::ScanCache(Environment *env) {
    e = env;
    s = new std::set<ScanResult *, ScanResultComperator>();
    hits = 0;
    misses = 0;
    pthread_mutex_init(&mutex, NULL);
}

/**
 * @brief Adds scan result to cache.
 * @param stat File status as returned by fstat()
 * @param response Response to be used for fanotify (FAN_ALLOW, FAN_DENY)
 */
void ScanCache::add(const struct stat *stat, const unsigned int response) {
    std::set<ScanResult *, ScanResultComperator>::iterator it;
    ScanResult *scr = new ScanResult();
    scr->dev = stat->st_dev;
    scr->ino = stat->st_ino;
    scr->mtime = stat->st_mtime;
    scr->response = response;
    gmtime(&(scr->age));

    pthread_mutex_lock(&mutex);
    it = s->find(scr);
    if (it != s->end()) {
        s->erase(it);
    }
    if (!s->insert(scr).second) {
        delete scr;
    }
    pthread_mutex_unlock(&mutex);
}

/**
 * @brief Adds scan result to cache.
 * @param stat file status as returned by fstat()
 * @return response to be used for fanotify (FAN_ALLOW, FAN_DENY) or CACHE_MISS
 */
int ScanCache::get(const struct stat *stat) {
    int ret;
    std::set<ScanResult *, ScanResultComperator>::iterator it;
    ScanResult *scr = new ScanResult();
    scr->dev = stat->st_dev;
    scr->ino = stat->st_ino;

    pthread_mutex_lock(&mutex);
    it = s->find(scr);
    delete scr;
    if (it == s->end()) {
        pthread_mutex_unlock(&mutex);
        ret = CACHE_MISS;
        misses++;
    } else {
        scr = *it;
        // Check modification time.
        if (scr->mtime == stat->st_mtime) {
            ret = scr->response;
            hits++;
        } else {
            delete *it;
            s->erase(it);
            ret = CACHE_MISS;
            misses++;
        }
    }
    pthread_mutex_unlock(&mutex);
    return ret;
}

/**
 * @brief Adds scan result to cache.
 * @param stat file status as returned by fstat()
 */
void ScanCache::remove(const struct stat *stat) {
    std::set<ScanResult *, ScanResultComperator>::iterator it;
    ScanResult *scr = new ScanResult();
    scr->dev = stat->st_dev;
    scr->ino = stat->st_ino;

    pthread_mutex_lock(&mutex);
    it = s->find(scr);
    if (it != s->end()) {
        delete *it;
        s->erase(it);
    }
    pthread_mutex_unlock(&mutex);
    delete scr;
}

ScanCache::~ScanCache() {
    std::set<ScanResult *, ScanResultComperator>::iterator pos;
    std::stringstream msg;
    for (pos = s->begin(); pos != s->end(); pos++) {
        delete *pos;
    }
    s->clear();
    pthread_mutex_destroy(&mutex);
    msg << "Cache hits " << hits << ", cache misses " << misses << ".";
    Messaging::message(Messaging::DEBUG, msg.str());
}
