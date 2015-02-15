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
#ifndef SCANCACHE_H
#define	SCANCACHE_H

#include <pthread.h>
#include <set>
#include <sys/stat.h>
#include <sys/types.h>
#include "Environment.h"

class Environment;

/**
 * @brief Result of scanning a file for viruses.
 */
struct ScanResult {
public:
    /**
     * @brief ID of device containing file.
     */
    dev_t dev;
    /**
     * @brief Inode number.
     */
    ino_t ino; /* inode number */
    /**
     * @brief Time of last modification.
     */
    time_t mtime; /* time of last modification */
    /**
     * @brief Result of scan.
     */
    unsigned int response; /* FAN_ALLOW or FAN_DENY */
    /**
     * @brief Time when this record entered the cache.
     */
    time_t age;
    /**
     * @brief Left neighbour in double linked list.
     */
    ScanResult *left;
    /**
     * @brief Right neighbour in double linked list.
     */
    ScanResult *right;
};

/**
 * @brief Compares two ScanResults.
 */
struct ScanResultComperator {
public:

    /**
     * @brief Compares two ScanResults.
     * @param value1 left ScanResult
     * @param value2 right ScanResult
     * @return 1 if value1 is less then value2, else 0
     */
    bool operator() (ScanResult *value1, ScanResult *value2) const {
        if (value1->dev < value2->dev) {
            return 1;
        } else if (value1->dev > value2->dev) {
            return 0;
        } else if (value1->ino < value2->ino) {
            return 1;
        } else {
            return 0;
        };
    }
};


/**
 * @brief Cache for virus scanning results.
 *
 * <p>The scan results are kept in two data structures:</p><ul>
 * <li>a double linked list with with <code>root</code> as left and right end
 * </li><li>an ordered set.</li></ul>
 * <p>The linked list is used for implementing a LRU (least recently used)
 * strategy. Accessed entries are brought to the  * left end of the double
 * linked list. When the cache exceeds its maximum size the rightmost element is
 * eliminated.</p>
 * <p> The set is used to find a scan result in O(log(n)) time.</p>
 */
class ScanCache {
public:
    /**
     * @brief No matching element found in cache.
     */
    static const unsigned int CACHE_MISS = 0xfffd;
    ScanCache(Environment *);
    void add(const struct stat *, const unsigned int);
    void clear();
    int get(const struct stat *);
    void remove(const struct stat *);
    virtual ~ScanCache();
private:
    /**
     * Cache data set.
     */
    std::set<ScanResult *, ScanResultComperator> *s;
    /**
     * @brief Mutex used when reading from or writing to the cache.
     */
    pthread_mutex_t mutex;
    /**
     * @brief Environment.
     */
    Environment *e;
    /**
     * @brief Number of cache misses.
     */
    unsigned long long misses;
    /**
     * @brief Number of cache hits.
     */
    unsigned long long hits;
    /**
     * @brief Root for double linked list.
     */
    ScanResult root;

    // Do not allow copying.
    ScanCache(const ScanCache&);
};

#endif	/* SCANCACHE_H */

