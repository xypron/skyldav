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
static void skipComment(FILE *file) {
    while (!feof(file)) {
        char c;
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
static void getToken(FILE *file, char *token, int *newline) {
    char c = 0x00;
    char *pos = token;
    int count = CONF_VALUE_MAX_LEN - 1;
    *token = 0x00;
    *newline = 0;

    // skip leading whitespace
    while (!feof(file)) {
        c = fgetc(file);
        if (c == '#') {
            skipComment(file);
            *newline = 1;
            return;
        } else if (c == '\n') {
            *newline = 1;
            return;
        } else if (c > ' ') {
            break;
        }
    }
    while (!feof(file)) {
        if (c < ' ') {
            *newline = 1;
            return;
        }
        switch (c) {
            case '#':
                skipComment(file);
                *newline = 1;
                return;
            case '\\':
                c = fgetc(file);
                if (feof(file) || c < ' ') {
                    *newline = 1;
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
int parseConfigurationFile(char *filename, conf_cb cb, void *info) {
    int newline = 0;
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
        getToken(file, key, &newline);
        if (newline || *key == 0x00) {
            continue;
        }
        if (*key == '=') {
            fprintf(stderr, "missing key in '%s'\n", filename);
            ret = 1;
            break;
        }
        getToken(file, value, &newline);
        if (strcmp(value, "=")) {
            fprintf(stderr, "missing '=' in '%s'\n", filename);
            ret = 1;
            break;
        }
        getToken(file, value, &newline);
        for (;;) {
            if (cb == NULL) {
                printf("%s = %s\n", key, value);
            } else {
                if (cb(key, value, info)) {
                    printf("Invalid entry in '%s': %s = %s\n",
                            filename, key, value);
                    ret = 1;
                };
            }
            if (newline) {
                break;
            }
            getToken(file, value, &newline);
            if (0 == strcmp(value, "")) {
                break;
            }
        }
    }
    fclose(file);
    return ret;
}
