/* 
 * File:   conf.h
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
 * @file conf.h
 * @brief Analyze configuration file.
 */

#ifndef CONF_H
#define	CONF_H

#ifdef	__cplusplus
extern "C" {
#endif

#define CONF_VALUE_MAX_LEN 512
    
    typedef int (*conf_cb)(const char *key, const char *value);
    
    int conf_parse(char *filename, conf_cb cb);

#ifdef	__cplusplus
}
#endif

#endif	/* CONF_H */

