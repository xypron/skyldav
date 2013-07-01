/* 
 * File:   Messaging.h
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
 * @file Messaging.h
 * @brief Send messages.
 */

#include <fstream>
#include <string>
#include <syslog.h>

#ifndef MESSAGING_H
#define	MESSAGING_H

/**
 * @brief Outputs messages to system and application log and to the console.
 */
class Messaging {
public:
    enum Level{
        DEBUG = 1,
        INFORMATION = 2,
        WARNING = 3,
        ERROR = 4
    };
    
    static void setLevel(const enum Level);
    static void error(const std::string);
    static void message(const enum Level, const std::string);
    static void teardown();
private:
    static Messaging *singleton;
    std::fstream logfs;
    enum Level messageLevel;

    Messaging();
    ~Messaging();
    static Messaging *getSingleton();
};

#endif	/* MESSAGING_H */

