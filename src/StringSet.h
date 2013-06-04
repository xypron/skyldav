/* 
 * File:  StringSet.h
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
 * @file StringSet.h
 * @brief Set of strings.
 */

#ifndef STRINGSET_H
#define	STRINGSET_H

#include <set>
#include <string>
#include <cstring>

/**
 * @brief Compares two strings.
 */
struct StringComperator {
public:

    /**
     * @brief Compares two strings.
     * @param value1 left string
     * @param value2 right string
     * @return value1 is less then value2
     */
    bool operator() (std::string *value1, std::string *value2) const {
        if (value1->compare(*value2) < 0) {
            return 1;
        } else {
            return 0;
        };
    }
};

/**
 * @brief Set of pointers to strings.
 */
class StringSet : std::set<std::string *, StringComperator> {
public:
    StringSet();
    void add(const char *value);
    using std::set<std::string *, StringComperator>::begin;
    using std::set<std::string *, StringComperator>::count;
    using std::set<std::string *, StringComperator>::end;
    using std::set<std::string *, StringComperator>::find;
    int find(const char *value);
    using std::set<std::string *, StringComperator>::iterator;
    void print();
    virtual ~StringSet();
private:
    /**
     * @brief Set of pointers to strings.
     */
//    typedef std::set<std::string *, StringComperator> _StringSetInternal;
//    _StringSetInternal strings;
};

#endif	/* STRINGSET_H */