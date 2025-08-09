#include "db_thread.h"
#include "log_db.h"
#include <time.h>

#define DB_BATCH_SIZE 10

extern sig_atomic_t db_get_signal;

void *db_thread_work(void *arg){
	time_t t = time(NULL);
	struct tm *time = localtime(&t);
	DBThreadInfo *info = (DBThreadInfo *)arg;
	MutexQueue *queue = info->queue;
	GlobalStats *stat = info->stat;
	if(queue == NULL){
		fprintf(stderr, "received null queueu\n");
	}
	DBop *db_op_buffer[DB_BATCH_SIZE];
	int current_buffer_cnt = 0;
	int res = connect_db();
	if(res != SQLITE_OK){
		fprintf(stderr, "DB Connect Fail\n");
		return NULL;
	}
	if(check_table_exist() != 0){
		create_table();
	}

	while(1){
		QueueMessage *deq_item = dequeue(queue);
		if(deq_item->type == QUEUE_ITEM_TYPE_SHUTDOWN){
			db_get_signal = 1;
			int loop_cnt = queue->size;
			printf("remain exec : %d\n", loop_cnt);
			if(current_buffer_cnt > 0){
				if(begin_transaction()!= -1){
				for(int i = 0; i< loop_cnt; i++){
					if(insert_op(db_op_buffer[i])== -1){
						atomic_fetch_add(&stat->g_drop_cnt,1);
						fprintf(stderr, "Failed to insert data!\n");
					}
					free(db_op_buffer[i]->matched_pattern);
					free(db_op_buffer[i]);
				}
				if(commit_transaction() != 0){
					rollback_transaction();
				}
			}
			}
			if(print_log(time) !=- 0){
				fprintf(stderr, "Failed to print log data\n");
			}
			free(deq_item);
			 clear_table();
			disconnect_db();
			return NULL;
		}
		if(deq_item == NULL){
			fprintf(stderr, "Failed to db item dequeue\n");
			continue;
		}
		DBop *op = deq_item->data.db_op;
		if(op == NULL){
			fprintf(stderr, "dequeued op data is NULL\n");
			free(deq_item);
			continue;
		}
		if(current_buffer_cnt < DB_BATCH_SIZE){
			db_op_buffer[current_buffer_cnt++] = op;
			free(deq_item);
		}
		if(current_buffer_cnt == DB_BATCH_SIZE){
			if(begin_transaction()!= -1){
				for(int i = 0; i< DB_BATCH_SIZE; i++){
					if(insert_op(db_op_buffer[i])== -1){
						atomic_fetch_add(&stat->g_drop_cnt,1);
						fprintf(stderr, "Failed to insert data!\n");
					}
					free(db_op_buffer[i]->matched_pattern);
					free(db_op_buffer[i]);
				}
				if(commit_transaction() != 0){
					rollback_transaction();
				}
			}
			current_buffer_cnt = 0;
			memset(db_op_buffer, 0, sizeof(db_op_buffer));
		}
	}
}


int create_db_thread(pthread_t *thread, DBThreadInfo *db_info){
	if(pthread_create(thread, NULL, db_thread_work, (void *)db_info) != 0){
		fprintf(stderr, "Failed to create db thread\n");
		return -1;
	}
	return 1;
}
