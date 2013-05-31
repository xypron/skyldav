/* 
 * File:   listmounts.c
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
 * @file listmounts.c
 * @brief List mounts.
 */

#include <libmount/libmount.h>
#include <stdio.h>
#include "listmounts.h"

static struct libmnt_context *cxt = NULL;
static struct libmnt_table *tb = NULL;
static struct libmnt_iter *itr = NULL;

/**
 * Initializes enumeration of mounts.
 * 
 * @return success
 */
int listmountinit() {
    int ret = 1;
    do {
        cxt = mnt_new_context();
        if (cxt == NULL) {
            fprintf(stderr, "Cannot retrieve context.\n");
            break;
        }
        if (mnt_context_get_mtab(cxt, &tb) || tb == NULL) {
            fprintf(stderr, "Cannot parse mtab.\n");
            break;
        }
        itr = mnt_new_iter(MNT_ITER_FORWARD);
        ret = 0;
    } while (0);
    return ret;
}

/**
 * Gets next mount.
 * 
 * @param dir directory
 * @param type type of mount
 * @return success
 */
int listmountnext(char **dir, char **type) {
    int ret = 1;
    struct libmnt_fs *fs;
    if (0 == mnt_table_next_fs(tb, itr, &fs)) {
        *dir = mnt_fs_get_target(fs);
        *type = mnt_fs_get_fstype(fs);
        ret = 0;
    }
    return ret;
}

/**
 * Finalizes enumeration of mounts.
 */
void listmountfinalize() {
    if (itr) {
        mnt_free_iter(itr);
        itr = NULL;
    };
    if (cxt) {
        mnt_free_context(cxt);
        cxt = NULL;
    }
}
