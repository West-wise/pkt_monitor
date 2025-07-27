#ifndef UTILS_H
#define UTILS_H

#include "common.h"
#include <signal.h>
#include "thread_set.h"
#include "queue_set.h"
#include "pattern.h"
#include "bm.h"


void usage();

void handleSignal(int signal, siginfo_t *info, void *context);

bool interface_check(const char *interface);

int mode_check(int mode, char *interface, int thread_cnt, char *advanced_file_path, char *pcap_file_path);

void atomic_init_func(GlobalStats *g_stats);

int init_pattern(const char *file_path);

void pattern_cleanup();

void print_hex_dump(const u_char *data_ptr, unsigned int len, unsigned int offset_start);

#endif