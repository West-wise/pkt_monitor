#ifndef TRHEAD_SET_H
#define THREAD_SET_H


#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h> // ntos, ntohl

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

typedef struct StackedValue {
	unsigned int s_tcp_pps, s_tcp_bps;
	unsigned int s_udp_pps, s_udp_bps;
	unsigned int s_icmp_pps, s_icmp_bps;
	unsigned int s_etc_pps, s_etc_bps;
	unsigned int s_det_pps,  s_det_bps;
} StackedValue;


typedef struct TotalValue {
	unsigned int total_pps, total_bps, total_drop;
	unsigned int t_tcp_pps, t_tcp_bps;
	unsigned int t_udp_pps, t_udp_bps;
	unsigned int t_icmp_pps, t_icmp_bps;
	unsigned int t_etc_pps, t_etc_bps;
	unsigned int t_det_pps, t_det_bps;
} TotalValue;

void sum_data(StackedValue *st_val, TotalValue *t_val);


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


int makeMsg(DBop *query_data, PacketInfo *pInfo, struct iphdr *ip_header, struct tcphdr *tcp_header);

#endif

