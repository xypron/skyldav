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

#include <set>
#include <sys/stat.h>
#include <sys/types.h>

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
    int response; /* FAN_ALLOW or FAN_DENY */    
    /**
     * @brief Time when this record entered the cache.
     */
    time_t age;
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
     * @return value1 is less then value2
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
 * @brief cache for virus scanning results.
 */
class ScanCache : std::set<ScanResult *, ScanResultComperator> {
public:
    ScanCache();
    void add(const struct stat *, const int);
    int get(const struct stat *);
    void remove(const struct stat *);
    virtual ~ScanCache();
private:

};

#endif	/* SCANCACHE_H */

