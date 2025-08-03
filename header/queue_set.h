#ifndef QUEUE_SET_H
#define QUEUE_SET_H


#define QUEUE_SIZE 1024

#include <pthread.h>
#include "common.h"
#include "utils.h"
// #include "thread_set.h"



typedef enum {
	QUEUE_ITEM_TYPE_UNKNOWN = 0,
	QUEUE_ITEM_TYPE_DB_OP,
	QUEUE_ITEM_TYPE_PACKET_INFO,
	QUEUE_ITEM_TYPE_SHUTDOWN
} QueueDataType;


typedef struct DBop{
	struct timeval time;
	uint8_t protocol;
	uint32_t src_ip;
	uint16_t src_port;
	uint32_t dst_ip;
	uint16_t dst_port;
	char *matched_pattern;
} DBop;

typedef struct PacketInfo{
	struct pcap_pkthdr header; // packet id
	unsigned char data[];	// sizeof()에서 계산이 안됨, 그래서 malloc()시 추가 할당 필요
}PacketInfo;


typedef struct QueueMessage {
	QueueDataType type;
	union{
		DBop *db_op;
		PacketInfo *packet_info;
	} data;
} QueueMessage;


typedef struct Node{
	void *data;
	struct Node *next;
}Node;


typedef struct MutexQueue {
	Node *front;
	Node *rear;
	int size; // current size
	int capacity;
	pthread_mutex_t lock;
	pthread_cond_t not_empty; // Condition variable for producers
	pthread_cond_t not_full; // Condition variable for consumers
	volatile int shutdown_flag;
} MutexQueue; 

typedef struct MutexQueueList {
	MutexQueue **mutexQueue;
	int num_of_queue;
} MutexQueueList;


typedef struct PcapHandlerArgs{
	MutexQueueList *queue_list;
	GlobalStats *handler_stats;
	
	int num_queues;
	int current_queue_id;
	// MemoryPool *packet_data_pool;
} PcapHandlerArgs;


void initQueue(MutexQueue *mq, int max_size);

int isEmpty(MutexQueue *mq);

int isFull(MutexQueue *mq);

int enqueue(MutexQueue *mq, QueueMessage *item); // for producers

QueueMessage *dequeue(MutexQueue *mq); // for consumers


void shutdownQueue(MutexQueue *mq);

void destroyQueue(MutexQueue *mq);

MutexQueueList *createQueueList(int thread_cnt);

void destroyQueueList(MutexQueueList *list);

MutexQueue *getQueue(MutexQueueList *list, int idx);

// void roundRobin();



#endif
