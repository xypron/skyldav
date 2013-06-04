/* 
 * File:   MountPolling.h
 * 
 * Copyright 2012 Heinrich Schuchardt <xypron.glpk@gmx.de>
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
 */

/**
 * @file MountPolling.h
 * @brief Poll /proc/mounts to detect mount events.
 */
#ifndef POLLMOUNTS_H
#define	POLLMOUNTS_H

#include "StringSet.h"

#ifdef	__cplusplus
extern "C" {
#endif

    /**
     * @brief Polls mount and unmout events
     */
    class MountPolling {
    public:
        /**
         * Pointer to callback function for polling mounts.
         */
        typedef void (*callbackptr)();
        /**
         * Initializes polling of mounts.
         * @param nomarkfs file systems that shall not be watched
         * @param nomarkmnt mounts that shall not be watched
         */
        static void init(StringSet *nomarkfs, StringSet *nomarkmnt);
        /**
         * Starts polling of mounts.
         */
        static int start();
        /**
         * Stops polling of mounts.
         */
        static int stop();
        /**
         * Callback function called when mount event occurs.
         */
        static void callback();
    private:
        static StringSet *mounts;
        static StringSet *nomarkfs;
        static StringSet *nomarkmnt;
    };


#ifdef	__cplusplus
}
#endif

#endif	/* POLLMOUNTS_H */

