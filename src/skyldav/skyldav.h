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
 * @brief On access virus scanner.
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
            "  -h               help\n"
            "  -m <n>           message level\n"
            "                     1 - Debug\n"
            "                     2 - Information, default\n"
            "                     3 - Warning\n"
            "                     4 - Error\n"
            "  -v               version\n\n"
            "Licensed under the Apache License, Version 2.0.\n"
            "Report errors to\n"
            "Heinrich Schuchardt <xypron.glpk@gmx.de>\n";

    const char *VERSION_TEXT =
            "On access virus scanner.\n\n"
            "Copyright 2013 Heinrich Schuchardt <xypron.glpk@gmx.de>\n\n"
            "Licensed under the Apache License, Version 2.0 (the\n"
            "\"License\"); you may not use this file except in compliance\n"
            "with the License. You may obtain a copy of the License at\n\n"
            "    http://www.apache.org/licenses/LICENSE-2.0\n\n"
            "Unless required by applicable law or agreed to in writing,\n"
            "software distributed under the License is distributed on an\n"
            "\"AS IS\" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,\n"
            "either express or implied. See the License for the specific\n"
            "language governing permissions and limitations under the\n"
            "License.\n";

    const char *PID_FILE = "/var/run/skyldav/skyldav.pid";
    
#ifdef	__cplusplus
}
#endif

#endif	/* SYKLDAV_H */

