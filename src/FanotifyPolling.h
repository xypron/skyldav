/* 
 * File:   FanotifyPolling.h
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
 *
 */

/**
 * @file FanotifyPolling.h
 * @brief Poll fanotify events.
 */

#ifndef POLLFANOTIFY_H
#define	POLLFANOTIFY_H

#include <sys/fanotify.h>

#ifdef	__cplusplus
extern "C" {
#endif

    /**
     * @brief Scan task.
     */
    struct ScanTask {
        /**
         * @brief fanotify file descriptor
         */
        int fd;
        /**
         * @brief fanotify metadata
         */
        struct fanotify_event_metadata metadata;
    };
       
    typedef void (*skyld_pollfanotifycallbackptr)(const int fd,
            const void *buf, int len);

    void skyld_displayfanotify(const int fd, const void *buf, int len);
    int skyld_pollfanotifystart(int nThread);
    int skyld_pollfanotifystop();
    int skyld_fanotifywriteresponse(const int fd, 
            const struct fanotify_response response);
    int skyld_pollfanotifymarkmount(const char *mount);
    int skyld_pollfanotifyunmarkmount(const char *mount);

#ifdef	__cplusplus
}
#endif

#endif	/* POLLFANOTIFY_H */
