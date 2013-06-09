/* 
 * File:   ThreadPool.h
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
 * @file ThreadPool.h
 * @brief Implements the thread pool pattern.
 */
#ifndef THREADPOOL_H
#define	THREADPOOL_H

#include <deque>
#include <pthread.h>

/**
 * @brief Implements the thread pool pattern.
 * 
 * A number of threads is created to perform tasks. Tasks are stored in a queue.
 * When a thread becomes available it completes a new task from the queue.
 */
class ThreadPool {
public:
    enum status {
        RUNNING,
        STOPPING
    };
    
    ThreadPool(int nThreads, void* (*workRoutine) (void *));
    void add(void *workItem);
    void *getWorkItem();
    virtual ~ThreadPool();
private:
    enum status status;
    int createThread();
    void exitThread(void *retval);
    int isStopping();
    pthread_cond_t cond;
    static void *worker (void *);
    pthread_mutex_t mutexThread;
    pthread_mutex_t mutexWorker;
    pthread_mutex_t mutexWorkItem;
    int nThreads;
    std::deque<void *> worklist;
    void* (*workRoutine) (void *);
};

#endif	/* THREADPOOL_H */

