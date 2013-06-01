/* 
 * File:  StringSet.c
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
 * @file StringSet.cc
 * @brief Set of strings.
 */

#include <iostream>
#include "StringSet.h"

/**
 * @brief Creates string set.
 */
StringSet::StringSet() {
}

/**
 * @brief Adds entry to string set.
 * @param value new entry.
 */
void StringSet::add(const char *value) {
    std::string *str = new std::string(value);
    if (!this->insert(str).second) {
        delete str;
    }
}

/**
 * @brief Finds entry in string set.
 * @param value entry
 * @return success
 */
int StringSet::find(const char *value) {
    int ret = 0;
    std::string *str = new std::string(value);
    if (this->end() != this->find(str)) {
        ret = 1;
    }
    delete str;
    return ret;
}

/**
 * @brief Prints content of string set to console.
 */
void StringSet::print() {
    StringSet::iterator pos;
    for (pos = this->begin(); pos != this->end(); pos++) {
        std::cout << "'" <<**pos << "'" << std::endl;
    }
}

/**
 * @brief Destroys stringset.
 */
StringSet::~StringSet() {
    StringSet::iterator pos;
    for (pos = this->begin(); pos != this->end(); pos++) {
        delete *pos;
    }
    this->clear();
}

