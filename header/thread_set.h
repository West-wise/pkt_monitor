#ifndef TRHEAD_SET_H
#define THREAD_SET_H

#include <stdatomic.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h> // ntos, ntohl
#include "common.h"
#include "queue_set.h"
#include "log_db.h"


/** task thread func **/
typedef struct PacketStats{
        _Atomic unsigned int packet_cnt;
        _Atomic unsigned int byte_cnt;
} PacketStats;

typedef struct GlobalStats{
        _Atomic unsigned int g_packet_cnt;
        _Atomic unsigned long long g_byte_cnt;
        _Atomic unsigned long g_drop_cnt;

        PacketStats tcp_stats;
        PacketStats udp_stats;
        PacketStats icmp_stats;
        PacketStats etc_stats;
} GlobalStats;

typedef struct WorkerThreadInfo{
        unsigned int thread_num;
        MutexQueue *queue;
        MutexQueue *db_queue;
        GlobalStats *g_stats;
} WorkerThreadInfo;

void *task_thread_work(void *args);


/**
 int count : number of thread
 pthread_t *thread_list : thread_list for wating thread join in main thread
 pQueue List : Queue List from each worker_thread
 * **/
int create_worker_thread(pthread_t *thread, MutexQueue *worker_queue,MutexQueue *db_queue,  GlobalStats *stats, int thread_num );




/** db thread func **/
void *db_thread_work(void *arg);

int create_db_thread(pthread_t *thread, MutexQueue *db_queue);




/** print thread func **/

typedef struct PrintArgs{
        GlobalStats **all_thread_stats;
        int thread_cnt;
}PrintArgs;

void *print_thread_work(void *args);

int create_printer_thread(pthread_t *thread, GlobalStats **all_stats,int thread_cnt);


#endif