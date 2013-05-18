/* 
 * File:   skyldav.h
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
 * @file skyldav.h
 * @brief Set of strings.
 */

#ifndef SYKLDAV_H
#define	SYKLDAV_H

#ifdef	__cplusplus
extern "C" {
#endif
    
    const char *CONF_FILE = "/etc/skyldav.conf";

    const char *HELP_TEXT =
            "Usage: skyldav [OPTION]\n"
            "On access virus scanner.\n\n"
            "  -c <configfile>  path to config file\n"
            "  -d               daemonize\n"
            "  -h               help\n\n"
            "Licensed under the Apache License, Version 2.0.\n"
            "Report errors to\n"
            "Heinrich Schuchardt <xypron.glpk@gmx.de>";

    const char *PID_FILE = "/var/run/skyldav/skyldav.pid";
    
#ifdef	__cplusplus
}
#endif

#endif	/* SYKLDAV_H */

