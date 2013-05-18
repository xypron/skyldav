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
 * @file StringSet.c
 * @brief Set of strings.
 */

#include "StringSet.h"

StringSet::StringSet() {
}

void StringSet::add(char *value) {
    std::string *str = new std::string(value);
    if (!this->strings.insert(str).second) {
        delete str;
    }
}

int StringSet::find(char *value) {
    int ret = 0;
    std::string *str = new std::string(value);
    if (this->strings.end() != this->strings.find(str)) {
        ret = 1;
    }
    delete str;
    return ret;
}

StringSet::~StringSet() {
    _StringSetInternal::iterator pos;
    for (pos = this->strings.begin(); pos != this->strings.end(); pos++) {
        delete *pos;
    }
    this->strings.clear();
}

