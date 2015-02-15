/*
 * File:   notify.h
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
 * @file notify.h
 * @brief Notify Skyld AV events.
 */

#ifndef NOTIFY_H
#define	NOTIFY_H

#ifdef	__cplusplus
extern "C" {
#endif

const char *HELP_TEXT =
    "Usage: skyldavnotify [OPTION]\n"
    "Notification for Skyld AV on access virus scanner.\n\n"
    "  -h               help\n"
    "  -v               version\n\n"
    "Licensed under the Apache License, Version 2.0.\n"
    "Report errors to\n"
    "Heinrich Schuchardt <xypron.glpk@gmx.de>\n";

const char *VERSION_TEXT =
    "Notification for Skyld AV on access virus scanner.\n\n"
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

#ifdef	__cplusplus
}
#endif

#endif	/* NOTIFY_H */

