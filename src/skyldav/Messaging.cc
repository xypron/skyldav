/* 
 * File:   Messaging.cc
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
 * @file Messaging.cc
 * @brief Send messages.
 */

#include <errno.h>
#include <iostream>
#include <malloc.h>
#include <libgen.h>
#include <sstream>
#include <string>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "config.h"
#include "Messaging.h"

Messaging *Messaging::singleton = NULL;

Messaging::Messaging() {
    char *path;
    char *filename;
    messageLevel = INFORMATION;
    logfs.exceptions(std::ifstream::failbit | std::ifstream::badbit);

    // Open syslog.
    setlogmask(LOG_UPTO(LOG_NOTICE));
    openlog("Skyld AV", 0, LOG_USER);

    // Create directory for logfile.
    filename = strdup(LOGFILE);
    path = dirname(filename);
    mkdir(path, 0755);
    free(filename);
    
    // Open logfile for append.
    logfs.open(LOGFILE, std::fstream::out | std::fstream::app);
}

void Messaging::error(const std::string label) {
    std::stringstream text;
    text << label << ": " << strerror(errno);
    message(ERROR, text.str());
}

void Messaging::message(const enum Level level, const std::string message) {
    std::string type;
    getSingleton();
    if (level < singleton->messageLevel) {
        return;
    }
    switch (level) {
        case ERROR:
            type = "E";
            syslog(LOG_ERR, "%s", message.c_str());
            std::cerr << message << std::endl;
            break;
        case WARNING:
            type = "W";
            syslog(LOG_WARNING, "%s", message.c_str());
            std::cerr << message << std::endl;
            break;
        case INFORMATION:
            type = "I";
            syslog(LOG_NOTICE, "%s", message.c_str());
            std::cout << message << std::endl;
            break;
        case DEBUG:
            type = "D";
            std::cout << message << std::endl;
            return;
        default:
            type = " ";
            std::cout << message << std::endl;
            break;
    }
    
    singleton->logfs << type << message << std::endl;
}

void Messaging::setLevel(const enum Level level) {
    getSingleton();
    singleton->messageLevel = level;
}

Messaging *Messaging::getSingleton() {
    if (singleton == NULL) {
        singleton = new Messaging();
    }
    return singleton;
}

void Messaging::teardown() {
    delete singleton;
}

Messaging::~Messaging() {
    closelog();
    logfs.close();
}

