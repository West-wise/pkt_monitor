#ifndef UTILS_H
#define UTILS_H

#include "common.h"
// #include "queue_set.h"


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
	PacketStats detected_stats;
} GlobalStats;

void usage();

// void handleSignal(int signal, siginfo_t *info, void *context);

bool interface_check(const char *interface);

int mode_check(int mode, char *interface, int thread_cnt, char *advanced_file_path, char *pcap_file_path);

void atomic_init_func(GlobalStats *g_stats);


#endif
