/* 
 * File:   pollfanotify.h
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
 * @file pollfanotify.h
 * @brief Poll fanotify events.
 */

#ifndef POLLFANOTIFY_H
#define	POLLFANOTIFY_H

#ifdef	__cplusplus
extern "C" {
#endif

    typedef void (*skyld_pollfanotifycallbackptr)(const int fd,
            const void *buf, int len);

    void skyld_displayfanotify(const int fd, const void *buf, int len);
    int skyld_pollfanotifystart(skyld_pollfanotifycallbackptr cbptr);
    int skyld_pollfanotifystop();
    int skyld_pollfanotifymarkmount(const char *mount);
    int skyld_pollfanotifyunmarkmount(const char *mount);

#ifdef	__cplusplus
}
#endif

#endif	/* POLLFANOTIFY_H */
