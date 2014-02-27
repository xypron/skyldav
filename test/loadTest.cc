/* 
 * File:   loadTest.cc
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
 * @file loadTest.cc
 * @brief Implements a load test.
 * A threadpool is created. The work list is filled with tasks to open and
 * close a file.
 */

#include <sstream>
#include <iostream>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "config.h"
#include "ScanCache.h"
#include "ThreadPool.h"

const char *VERSION_TEXT_LOADTEST =
        "Load test for on access virus scanner.\n\n"
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

const char *HELP_TEXT_LOADTEST =
        "Usage: loadTest [OPTION]\n"
        "Load test for access virus scanner.\n\n"
        "  -h               help\n"
        "  -n <n>           number of threads [1..128]\n"
        "  -v               version\n\n"
        "Licensed under the Apache License, Version 2.0.\n"
        "Report errors to\n"
        "Heinrich Schuchardt <xypron.glpk@gmx.de>\n";

/**
 * @brief Task.
 */
struct Task {
    /**
     * @brief id
     */
    int id;
    /**
     * @brief filename
     */
    const char *filename;
};

/**
 * Status
 */
enum {
    RUNNING = 1,
    TERMINATING = 2
} status;

/**
 * @brief Handles signal.
 * 
 * @param sig signal
 */
static void hdl(int sig) {
    status = TERMINATING;
    fprintf(stderr, "Terminating\n");
}

/**
 * @brief Open and close one file.
 */
static void* work(void *workitem) {
    Task *task = static_cast<Task *> (workitem);
    int fd;

    fd = open(task->filename, O_RDONLY);
    if (fd == -1) {
        perror("Failure to open file");
    } else {
        int ret = close(fd);
        if (ret == -1) {
            perror("Failure to close file");
        }
    }

    delete task;
    return NULL;
}

/**
 * @brief Prints help message and exits.
 */
static void help() {
    printf("%s", HELP_TEXT_LOADTEST);
    exit(EXIT_FAILURE);
}

/**
 * @brief Shows version information and exits.
 */
static void version() {
    printf("Skyld AV load test, version %s\n", VERSION);
    printf("%s", VERSION_TEXT_LOADTEST);
    exit(EXIT_SUCCESS);
}

/**
 * @brief Main.
 */
int main(int argc, char** argv) {
    // action to take when signal occurs
    struct sigaction act;
    // signal mask
    sigset_t blockset;
    // thread pool
    ThreadPool *tp;
    // index
    int i;
    // number of threads
    int nThread;
    // number of tasks
    int nTask = 10000;
    Task *task;

    // Set the number of threads to the number of available CPUs.
    nThread = sysconf(_SC_NPROCESSORS_ONLN);
    if (nThread < 4) {
        // Use at least one thread.
        nThread = 4;
    }

    // Analyze command line options.
    for (i = 1; i < argc; i++) {
        // command line option
        char *opt;

        opt = argv[i];
        if (*opt == '-') {
            opt++;
        } else {
            help();
        }
        if (*opt == '-') {
            opt++;
        }
        switch (*opt) {
            case 'n':
                i++;
                if (i < argc) {
                    std::istringstream(argv[i]) >> nThread;
                } else {
                    help();
                }
                if (nThread > 128
                        || nThread < 1) {
                    help();
                }
                break;
            case 'v':
                version();
                ;
                break;
            default:
                help();
        }
    }

    // Set status
    status = RUNNING;

    // Block signals.
    sigemptyset(&blockset);
    sigaddset(&blockset, SIGUSR1);
    if (sigprocmask(0 * SIG_BLOCK, &blockset, NULL) == -1) {
        perror("main, sigmaskprocmask");
        return EXIT_FAILURE;
    }
    // Set handler for SIGTERM.
    act.sa_handler = hdl;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    if (sigaction(SIGTERM, &act, NULL)
            || sigaction(SIGINT, &act, NULL)
            || sigaction(SIGUSR1, &act, NULL)) {
        perror("main, sigaction");
        return EXIT_FAILURE;
    }

    std::cout << "Number of worker threads = " << nThread << std::endl
            << "Terminate with CTRL+C" << std::endl;

    tp = new ThreadPool(nThread, work);

    for (;;) {
        struct timespec interval = {
            0,
            1000000
        };
        if (tp->getWorklistSize() < nTask) {
            for (i = 0; i < nTask; i++) {
                task = new Task;
                task->id = i;
                task->filename = argv[0];
                tp->add((void *) task);
                if (status != RUNNING) {
                    break;
                }
            }
        } else {
            nanosleep(&interval, NULL);
        }
        if (status != RUNNING) {
            break;
        }
    }
    delete tp;
    return 0;
}
