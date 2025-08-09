#ifndef PRINTER_THREAD_H
#define PRINTER_THREAD_H

#include "common.h"
#include "utils.h"

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

typedef struct PrintArgs{
	GlobalStats **all_thread_stats;
	int thread_cnt;
} PrintArgs;

void sum_data(StackedValue *st_val, TotalValue *t_val);

void *print_thread_work(void *args);

int create_printer_thread(pthread_t *thread, GlobalStats **all_stats,int thread_cnt);

#endif
