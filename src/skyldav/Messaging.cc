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
#include "skyldav.h"
#include "Messaging.h"

Messaging *Messaging::singleton = NULL;

Messaging::Messaging() {
    char *path;
    char *filename;
    mode_t mask;

    // Filter debug messages by default.
    messageLevel = INFORMATION;
    logfs.exceptions(std::ifstream::failbit | std::ifstream::badbit);

    // Open syslog.
    setlogmask(LOG_UPTO(LOG_NOTICE));
    openlog(SYSLOG_ID , 0, LOG_USER);

    // Set umask = 022;
    mask = umask(S_IWGRP | S_IWOTH);

    // Create directory for logfile.
    filename = strdup(LOGFILE);
    path = dirname(filename);
    mkdir(path, 0755);
    free(filename);

    // Open logfile for append.
    try {
        logfs.open(LOGFILE, std::fstream::out | std::fstream::app);
        if (-1 == chmod(LOGFILE, 0644)) {
            std::cerr << "Failure to set mask for logfile." << std::endl;
        }
    } catch (class std::ios_base::failure ex) {
        std::cerr << "Failure to open logfile." << std::endl;
    }

    // Reset umask.
    umask(mask);
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
    try {
        singleton->logfs << type << message << std::endl;
    } catch (class std::ios_base::failure ex) {
        std::cerr << "Failure to write to logfile." << std::endl;
    }

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
    try {
        logfs.close();
    } catch (class std::ios_base::failure ex) {
        std::cerr << "Failure to close logfile." << std::endl;
    }
}

