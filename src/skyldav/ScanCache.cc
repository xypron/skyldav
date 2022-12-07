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

/**
 * Creates cache for virus scan results.
 * @param env environment
 */
ScanCache::ScanCache(Environment *env) {
    e = env;
    s = new std::set<ScanResult *, ScanResultComperator>();
    hits = 0;
    misses = 0;
    // Initialize mutex.
    pthread_mutex_init(&mutex, NULL);
    // Initialize the double linked list of scan results.
    clear();
}

/**
 * @brief Adds scan result to cache.
 * @param stat File status as returned by fstat()
 * @param response Response to be used for fanotify (FAN_ALLOW, FAN_DENY)
 */
void ScanCache::add(const struct stat *stat, const unsigned int response) {
    std::set<ScanResult *, ScanResultComperator>::iterator it;
    std::pair < std::set<ScanResult *, ScanResultComperator>::iterator, bool> pair;
    unsigned int cacheMaxSize = e->getCacheMaxSize();

    if (0 == cacheMaxSize) {
        return;
    }

    ScanResult *scr = new ScanResult();
    scr->dev = stat->st_dev;
    scr->ino = stat->st_ino;
    scr->mtime = stat->st_mtime;
    scr->response = response;
    gmtime(&(scr->age));

    pthread_mutex_lock(&mutex);
    it = s->find(scr);
    if (it != s->end()) {
        // Old matching entry found. Remove from linked list and delete.
        (*it)->left->right = (*it)->right;
        (*it)->right->left = (*it)->left;
        delete *it;
        s->erase(it);
    } else while (s->size() >= cacheMaxSize) {
            // Cache size too big. Get last element.
            it = s->find(root.left);
            if (it != s->end()) {
                // Remove from linked list and delete.
                (*it)->left->right = (*it)->right;
                (*it)->right->left = (*it)->left;
                delete *it;
                s->erase(it);
            } else {
                break;
            }
        }
    pair = s->insert(scr);
    if (pair.second) {
        // Successful insertion. Introduce leftmost in linked list.
        root.right->left = scr;
        scr->right = root.right;
        scr->left = &root;
        root.right = scr;
    } else {
        // element already existed
        delete scr;
    }
    pthread_mutex_unlock(&mutex);
}

/**
 * @brief Removes all entries from the cache.
 */
void ScanCache::clear() {
    pthread_mutex_lock(&mutex);
    std::set<ScanResult *, ScanResultComperator>::iterator pos;
    for (pos = s->begin(); pos != s->end(); ++pos) {
        delete *pos;
    }
    s->clear();
    // Initialize the double linked list of scan results.
    root.left = &root;
    root.right = &root;
    Messaging::message(Messaging::DEBUG, "Cache cleared.");
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
        ret = CACHE_MISS;
        misses++;
    } else {
        scr = *it;
        // Check modification time.
        if (scr->mtime == stat->st_mtime) {
            // Element is valid. Remove it from linked list.
            scr->left->right = scr->right;
            scr->right->left = scr->left;
            // Insert it leftmost.
            root.right->left = scr;
            scr->right = root.right;
            scr->left = &root;
            root.right = scr;
            ret = scr->response;
            hits++;
        } else {
            // Remove outdated element from linked list and delete it.
            (*it)->left->right = (*it)->right;
            (*it)->right->left = (*it)->left;
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
 * @brief Remove scan result from cache.
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
        // Remove from linked list and delete.
        (*it)->left->right = (*it)->right;
        (*it)->right->left = (*it)->left;
        delete *it;
        s->erase(it);
    }
    pthread_mutex_unlock(&mutex);
    delete scr;
}

ScanCache::~ScanCache() {
    std::stringstream msg;
    msg << "Cache size " << s->size() <<
        ", cache hits " << hits << ", cache misses " << misses << ".";
    clear();
    delete s;
    pthread_mutex_destroy(&mutex);
    Messaging::message(Messaging::INFORMATION, msg.str());
}
