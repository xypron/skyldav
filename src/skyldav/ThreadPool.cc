/*
 * File:   ThreadPool.cc
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
 */

/**
 * @file ThreadPool.cc
 * @brief Implements the thread pool pattern.
 */
#include <sstream>
#include <pthread.h>
#include <time.h>
#include "ThreadPool.h"

/**
 * @brief Creates a new thread pool.
 *
 * @param nThreads number of threads to be created
 * @param workRoutine routine that handles the individual units of work
 */
ThreadPool::ThreadPool(int nThreads, void* (*workRoutine) (void *)) {
    int i;
    std::ostringstream name;

    thread_count = 0;
    status = RUNNING;
    this->workRoutine = workRoutine;
    pthread_mutex_init(&mutexThread, NULL);
    pthread_mutex_init(&mutexWorker, NULL);
    pthread_mutex_init(&mutexWorkItem, NULL);
    pthread_cond_init(&cond, NULL);

    /* Limit the number of threads. */
    if (nThreads > 256) {
        nThreads = 256;
    } else if (nThreads < 1) {
        nThreads = 1;
    }
    for (i = 1; i <= nThreads; i++) {
        name.str("");
        name << "skyldav-" << i;
        createThread(name.str().c_str());
    }
    return;
}

/**
 * @brief Adds a work item to the work list.
 *
 * @param workItem work item
 */
void ThreadPool::add(void *workItem) {
    pthread_mutex_lock(&mutexWorkItem);
    worklist.push_back(workItem);
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&mutexWorkItem);
}

/**
 * @brief Creates a new worker thread.
 *
 * @param name thread name or NULL
 * @return success = 0
 */
int ThreadPool::createThread(const char *name) {
    int ret;
    pthread_t thread;

    if (pthread_create(&thread, NULL, worker, this)) {
        ret = 1;
    } else {
        if (name) {
            ret = pthread_setname_np(thread, name);
        }
        pthread_mutex_lock(&mutexThread);
        thread_count++;
        pthread_mutex_unlock(&mutexThread);
        ret = 0;
    }
    return ret;
}

/**
 * @brief Exits a worker thread.
 *
 * @param retval return value
 */
void ThreadPool::exitThread(void *retval) {
    pthread_mutex_lock(&mutexThread);
    thread_count--;
    pthread_mutex_unlock(&mutexThread);
    pthread_cond_signal(&cond);
    pthread_exit(retval);
}

/**
 * @brief Gets a work item.
 *
 * @return work item or NULL
 */
void *ThreadPool::getWorkItem() {
    void *ret = NULL;

    if (pthread_mutex_lock(&mutexWorkItem)) {
        return NULL;
    }
    if (worklist.size()) {
        ret = worklist[0];
        worklist.pop_front();
    }
    pthread_mutex_unlock(&mutexWorkItem);
    return ret;
}

/**
 * @brief Gets size of worklist.
 *
 * @return size of worklist, -1 signals error
 */
long ThreadPool::getWorklistSize() {
    long ret = -1;
    if (pthread_mutex_lock(&mutexWorkItem)) {
        return ret;
    }
    ret = worklist.size();
    pthread_mutex_unlock(&mutexWorkItem);
    return ret;
}

/**
 * @brief Is thread pool stopping.
 *
 * @return thread pool is stopping
 */
int ThreadPool::isStopping() const {
    return status == STOPPING;
}

/**
 * @brief Working thread.
 *
 * @param threadPool thread pool
 * @return return value
 */
void * ThreadPool::worker(void *threadPool) {
    ThreadPool *tp;

    tp = static_cast<ThreadPool *> (threadPool);

    for (;;) {
        void *workitem;
        pthread_mutex_lock(&tp->mutexWorker);
        while (!tp->isStopping() && tp->worklist.size() == 0) {
            pthread_cond_wait(&tp->cond, &tp->mutexWorker);
        }
        pthread_mutex_unlock(&tp->mutexWorker);
        workitem = tp->getWorkItem();
        if (workitem != NULL) {
            if (tp->workRoutine) {
                (*tp->workRoutine)(workitem);
            }
        } else if (tp->isStopping()) {
            break;
        }
    }
    tp->exitThread(NULL);
    return NULL;
}

/**
 * @brief Deletes thread pool.
 */
ThreadPool::~ThreadPool() {
    int n;
    struct timespec interval = {
        0,
        1000000
    };

    pthread_mutex_lock(&mutexWorker);
    status = STOPPING;
    pthread_mutex_unlock(&mutexWorker);

    do {
        pthread_cond_signal(&cond);
        nanosleep(&interval, NULL);
        pthread_mutex_lock(&mutexThread);
        n = thread_count;
        pthread_mutex_unlock(&mutexThread);
    } while (n > 0);

    pthread_cond_destroy(&cond);
    pthread_mutex_destroy(&mutexWorkItem);
    pthread_mutex_destroy(&mutexWorker);
    pthread_mutex_destroy(&mutexThread);
    return;
}

