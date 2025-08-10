#ifndef DB_THREAD_H
#define DB_THREAD_H

#include "common.h"
#include "queue_set.h"

typedef struct DBThreadInfo{
	MutexQueue *queue;
	GlobalStats *stat;
} DBThreadInfo;

void *db_thread_work(void *arg);

int create_db_thread(pthread_t *thread, DBThreadInfo *db_info);

#endif
