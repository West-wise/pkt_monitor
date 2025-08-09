#include "printer_thread.h"

extern sig_atomic_t db_get_signal;

void sum_data(StackedValue *st_val, TotalValue *t_val){
	t_val->t_tcp_pps += st_val->s_tcp_pps;
	t_val->t_tcp_bps += st_val->s_tcp_bps;
	t_val->t_udp_bps += st_val->s_udp_bps;
	t_val->t_udp_pps += st_val->s_udp_pps;
	t_val->t_etc_bps += st_val->s_etc_bps;
	t_val->t_etc_pps += st_val->s_etc_pps;
	t_val->t_det_bps += st_val->s_det_bps;
	t_val->t_det_pps += st_val->s_det_pps;
}

void *print_thread_work(void *args){
	PrintArgs *print_args = (PrintArgs*)args;

	if(print_args == NULL){
		fprintf(stderr, "printer job func received NULL\n");
		return NULL;
	}

	GlobalStats **all_thread_stats = print_args->all_thread_stats;
	int num = print_args->thread_cnt;
	TotalValue t_val = {0};
	while(1){
		if(db_get_signal == 1){
			printf("\n\n ======== Final Report (PPS/BPS) ======== \n");
			printf("--------------------------------------------\n");
			printf("%-15s %12s %12s\n", "Protocol", "Bytes", "Packets");
			printf("--------------------------------------------\n");
			printf("%-15s %12u %12u\n", "Total", t_val.total_bps, t_val.total_pps);
			printf("%-15s %12u %12u\n", "TCP", t_val.t_tcp_bps, t_val.t_tcp_pps);
			printf("%-15s %12u %12u\n", "UDP", t_val.t_udp_bps, t_val.t_udp_pps);
			printf("%-15s %12u %12u\n", "ICMP", t_val.t_icmp_bps, t_val.t_icmp_pps);
			printf("%-15s %12u %12u\n", "ETC", t_val.t_etc_bps, t_val.t_etc_pps);
			printf("--------------------------------------------\n");
			printf("%-15s %12u %12u\n", "DET", t_val.t_det_bps, t_val.t_det_pps);
			printf("--------------------------------------------\n");
			printf("%-15s %25u\n", "DROP", t_val.total_drop);
			printf("============================================\n\n");
			return NULL;
		}
		StackedValue st_val = {0};
		for(int k = 0; k<num; k++){
			t_val.total_pps += atomic_exchange(&all_thread_stats[k]->g_packet_cnt,0);
			t_val.total_bps += atomic_exchange(&all_thread_stats[k]->g_byte_cnt, 0);
			t_val.total_drop += atomic_exchange(&all_thread_stats[k]->g_drop_cnt,0);

			st_val.s_tcp_pps += atomic_exchange(&all_thread_stats[k]->tcp_stats.packet_cnt,0);
			st_val.s_tcp_bps += atomic_exchange(&all_thread_stats[k]->tcp_stats.byte_cnt,0);

			st_val.s_udp_pps += atomic_exchange(&all_thread_stats[k]->udp_stats.packet_cnt, 0);
			st_val.s_udp_bps += atomic_exchange(&all_thread_stats[k]->udp_stats.byte_cnt, 0);

			st_val.s_icmp_pps += atomic_exchange(&all_thread_stats[k]->icmp_stats.packet_cnt,0);
			st_val.s_icmp_bps += atomic_exchange(&all_thread_stats[k]->icmp_stats.byte_cnt,0);

			st_val.s_etc_pps += atomic_exchange(&all_thread_stats[k]->etc_stats.packet_cnt,0);
			st_val.s_etc_bps += atomic_exchange(&all_thread_stats[k]->etc_stats.byte_cnt, 0);

			st_val.s_det_bps += atomic_exchange(&all_thread_stats[k]->detected_stats.byte_cnt,0);
			st_val.s_det_pps += atomic_exchange(&all_thread_stats[k]->detected_stats.packet_cnt,0);
		}
		printf("\n ====== Report(PPS/BPS) ====== \n");
		printf("TCP:\n\tPPS: %u\n\tBPS: %u\n", st_val.s_tcp_pps, st_val.s_tcp_bps);
		printf("UDP:\n\tPPS: %u\n\tBPS: %u\n", st_val.s_udp_pps, st_val.s_udp_bps);
		printf("ICMP:\n\tPPS: %u\n\tBPS: %u\n", st_val.s_icmp_pps, st_val.s_icmp_bps);
		printf("ETC:\n\tPPS: %u\n\tBPS: %u\n", st_val.s_etc_pps, st_val.s_etc_bps);
		printf("DET:\n\tPPS: %u\n\tBPS: %u\n", st_val.s_det_bps, st_val.s_det_pps);
		printf(" =============================== \n");
		sum_data(&st_val, &t_val);
		sleep(1);
	}

	return NULL;
}


int create_printer_thread(pthread_t *thread, GlobalStats **all_stats, int thread_cnt){

	PrintArgs *args = (PrintArgs*)malloc(sizeof(PrintArgs));
	if(args == NULL){
		fprintf(stderr, "Failed to malloc printer thread args\n");
		return -1;
	}
	args->all_thread_stats = all_stats;
	args->thread_cnt = thread_cnt + 2;
	if(pthread_create(thread, NULL, print_thread_work, (void*)args) != 0){
		fprintf(stderr, "Failed to create woker thread\n");
		free(args);
		return -1;
	}
	// free(args); // Bug fix applied
	return 1;
}
