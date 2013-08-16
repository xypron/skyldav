/* 
 * File:   conf.c
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
 * @file conf.c
 * @brief Analyze configuration file.
 * 
 * <p>Each assignement line must have a key and a value separated by an equal
 * sign.</p>
 * <pre>key = value</pre>
 * <p>Comments start with a number sign.</p>
 * <pre>This is a comment.</pre>
 * <p>Multiple values on a line must be separated by comma.</p>
 * <pre>key = value1, value2</pre>
 * <p>Alternatively multiple lines may be used.</p>
 * <pre>key = value1
 * key = value2</pre>
 * <p>Use backslashs to escape ' ', ',', '#' and '\'.</p>
 * <pre>key = value\ with\ spaces</pre>
 * <p>Lines may be empty.</p>
 */

#include <stdio.h>
#include <string.h>
#include "conf.h"

/**
 * @brief Skips comment.
 * @param file file
 */
static void skipcomment(FILE *file) {
    char c;
    while (!feof(file)) {
        c = fgetc(file);
        if (c == '\n') {
            break;
        }
    }
}

/**
 * @brief Gets token.
 * @param file file
 * @param token token
 */
static void gettoken(FILE *file, char *token) {
    char c;
    char *pos = token;
    int count = CONF_VALUE_MAX_LEN - 1;
    *token = 0x00;

    // skip leading whitespace
    while (!feof(file)) {
        c = fgetc(file);
        if (c == '#') {
            skipcomment(file);
        } else if (c == '\n') {
            return;
        } else if (c > ' ') {
            break;
        }
    }
    while (!feof(file)) {
        if (c <= ' ') {
            return;
        }
        switch (c) {
            case '#':
                skipcomment(file);
                return;
            case '\\':
                c = fgetc(file);
                if (feof(file) || c < ' ') {
                    return;
                }
                break;
            case ' ':
            case ',':
                return;
        }
        if (count > 0) {
            *pos = c;
            pos++;
        }
        *pos = 0x00;
        count--;
        c = fgetc(file);
    }
}

/**
 * @brief Parses configuration file.
 * If cb is NULL the key value pairs are output to the console.
 * Returns 0 if successful.
 * @param filename file name
 * @param cb callback function
 * @prame info parameter passed to callback function
 * @return success
 */
int conf_parse(char *filename, conf_cb cb, void *info) {
    int ret = 0;
    FILE *file;
    char key[CONF_VALUE_MAX_LEN];
    char value[CONF_VALUE_MAX_LEN];

    file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "file '%s' not found\n", filename);
        return 1;
    }

    while (!feof(file)) {
        gettoken(file, key);
        if (*key == 0x00) {
            continue;
        }
        if (*key == '=') {
            fprintf(stderr, "missing key in '%s'\n", filename);
            ret = 1;
            break;
        }
        gettoken(file, value);
        if (strcmp(value, "=")) {
            fprintf(stderr, "missing '=' in '%s'\n", filename);
            ret = 1;
            break;
        }
        for (;;) {
            gettoken(file, value);
            if (0 == strcmp(value, "")) {
                break;
            } else {
                if (cb == NULL) {
                    printf("%s = %s\n", key, value);
                } else {
                    if (cb(key, value, info)) {
                    printf("Invalid entry in '%s': %s = %s\n", 
                            filename, key, value);
                        ret = 1;
                    };
                }
            }
        }
    }
    fclose(file);
    return ret;
}
