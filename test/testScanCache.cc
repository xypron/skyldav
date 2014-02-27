/* 
 * File:   testScanCache.cc
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


#include <malloc.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include "ScanCache.h"
#include "Environment.h"
#include "Messaging.h"

static void checkEqual(const unsigned int actual, const unsigned int expected,
        const char *lbl) {
    if (actual != expected) {
        printf("%s: actual '%u', expected '%u'.\n", lbl, actual, expected);
        throw EXIT_FAILURE;
    }
}

int main(int argc, char *argv[]) {
    int ret = EXIT_SUCCESS;
    ScanCache *c;
    Environment *e;
    struct stat *stat;

    stat = (struct stat *) malloc(sizeof (struct stat));

    Messaging::setLevel(Messaging::DEBUG);
    e = new Environment();
    c = e->getScanCache();

    try {
        // Check basic insert, remove, get logic.
        stat->st_dev = 13;
        stat->st_ino = 100;
        stat->st_mtime = 1000;

        checkEqual(c->get(stat), ScanCache::CACHE_MISS, "Search in empty set");

        c->add(stat, 1);
        checkEqual(c->get(stat), 1, "Search after insert");

        c->add(stat, 2);
        checkEqual(c->get(stat), 2, "Search after replace");

        stat->st_dev = 12;
        stat->st_ino = 100;
        checkEqual(c->get(stat), ScanCache::CACHE_MISS, "Search lower dev");

        stat->st_dev = 14;
        stat->st_ino = 100;
        checkEqual(c->get(stat), ScanCache::CACHE_MISS, "Search higher dev");

        stat->st_dev = 13;
        stat->st_ino = 99;
        checkEqual(c->get(stat), ScanCache::CACHE_MISS, "Search lower inode");

        stat->st_dev = 13;
        stat->st_ino = 101;
        checkEqual(c->get(stat), ScanCache::CACHE_MISS, "Search higher inode");

        c->add(stat, 3);
        checkEqual(c->get(stat), 3, "Search after insert");

        c->remove(stat);
        checkEqual(c->get(stat), ScanCache::CACHE_MISS, "Search after remove");

        // Check that changes in time lead to deletion from cache.
        stat->st_dev = 1;
        stat->st_ino = 99;
        stat->st_mtime = 100;
        c->add(stat, 1);
        checkEqual(c->get(stat), 1, "Search after insert");
        stat->st_mtime = 101;
        checkEqual(c->get(stat), ScanCache::CACHE_MISS,
                "Search after time change (2)");
        stat->st_mtime = 100;
        checkEqual(c->get(stat), ScanCache::CACHE_MISS,
                "Search time reset");

        // Check that cache size is considered.
        e->setCacheMaxSize(500);
        stat->st_dev = 1;
        stat->st_mtime = 100;

        for (stat->st_ino = 1000; stat->st_ino > 0; stat->st_ino--) {
            c->add(stat, 3);
        }
        for (stat->st_ino = 1; stat->st_ino <= 1000; stat->st_ino++) {
            if (c->get(stat) == ScanCache::CACHE_MISS) {
                break;
            }
        }
        checkEqual(stat->st_ino, 501, "Cache size");

        e->setCacheMaxSize(50);
        stat->st_dev = 2;
        stat->st_mtime = 100;

        for (stat->st_ino = 100; stat->st_ino > 0; stat->st_ino--) {
            c->add(stat, 3);
        }
        for (stat->st_ino = 1; stat->st_ino <= 100; stat->st_ino++) {
            if (c->get(stat) == ScanCache::CACHE_MISS) {
                break;
            }
        }
        checkEqual(stat->st_ino, 51, "Cache resize");
        
        
    } catch (int ex) {
        ret = ex;
    }

    delete e;
    free(stat);
    Messaging::teardown();
    return ret;
}
