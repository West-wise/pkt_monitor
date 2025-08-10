#ifndef WORKER_THREAD_H
#define WORKER_THREAD_H

#include "common.h"
#include "queue_set.h"
#include "log_db.h"
#include "trie.h"

typedef struct WorkerThreadInfo{
	unsigned int thread_num;
	MutexQueue *queue;
	MutexQueue *db_queue;
	GlobalStats *g_stats;
} WorkerThreadInfo;

void *task_thread_work(void *args);

int create_worker_thread(pthread_t *thread, MutexQueue *worker_queue, MutexQueue *db_queue,  GlobalStats *stats, int thread_num);

#endif
