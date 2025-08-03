#define _GNU_SOURCE
#include "thread_set.h"
#include <inttypes.h>

#define DB_BATCH_SIZE 10

extern TrieNode *trie;

sig_atomic_t db_get_signal = 0;

int makeMsg(DBop *query_data, PacketInfo *pInfo, struct iphdr *ip_header, struct tcphdr *tcp_header){
	query_data->time = pInfo->header.ts;
	query_data->protocol = ip_header->protocol;
	query_data->src_ip = ip_header->saddr;
	query_data->src_port = ntohs(tcp_header->source);
	query_data->dst_ip = ip_header->daddr;
	query_data->dst_port = ntohs(tcp_header->dest);
	
	const char *http_payload = (char *)tcp_header + (tcp_header->doff*4);
	// const char *host_header = strstr(http_payload, "Host: ");
	size_t payload_len = ntohs(ip_header->tot_len) - (ip_header->ihl*4) - (tcp_header->doff*4);
	const char *host_header = memmem(http_payload, payload_len, "Host: ", 6);
	if(host_header){
		host_header += 10;
		const char *eol = strchr(host_header, '\r');
		if(eol){
			char host[100];
			size_t hostname_len = eol - host_header;
			snprintf(host, sizeof(host), "%.*s",(int)hostname_len, host_header);
			if(find(trie, host) == 0){
				// printf("find host\n");
				printf("find host : %s\n", host);
				query_data->matched_pattern = (char*)malloc(hostname_len+1);
				if(query_data->matched_pattern == NULL){
					fprintf(stderr, "Failed to malloc matched_pattern\n");
					return -1;
				}
				snprintf(query_data->matched_pattern, hostname_len+1, "%.*s",(int)hostname_len, host_header);
			}else{
				return -1;
			}
		}
	
	}else{
		return -1;
	}
	return 0;
}


void *task_thread_work(void *args){
	WorkerThreadInfo *wti = (WorkerThreadInfo*)args;
	int thread_num = wti->thread_num;
	MutexQueue *queue = wti->queue;
	MutexQueue *db_queue = wti->db_queue;
	GlobalStats *global_stats = wti->g_stats;

	sig_atomic_t expected = 0;
	sig_atomic_t desired = 1;
	int drop_flag = 0;

	while(1){
		QueueMessage *dequeued_item = dequeue(queue);
		if(dequeued_item == NULL){
			fprintf(stderr, "Worker Thread No.%d dequeue error, drop packet\n", thread_num);
			continue;
		}
		if(dequeued_item->type == QUEUE_ITEM_TYPE_SHUTDOWN){ // 종료 메세지, 자원 정리 해야함
			// 종료
			// db_get_signal 플래그를 1로 변경(여러 스레드에서 접근할 수 있으니 원자적 연산으로 진행)
			// 실패했다면 이미 다른 스레드가 변경 한 것
			if(!atomic_compare_exchange_strong(&db_get_signal,&expected,desired)){
				free(dequeued_item);
				break;
			}
			
			QueueMessage *db_shutdown_msg = (QueueMessage *)malloc(sizeof(QueueMessage));
			if(db_shutdown_msg == NULL){
				fprintf(stderr, "Failed to malloc db_shutdown msg\n");
				free(dequeued_item);
				atomic_fetch_add(&global_stats->g_drop_cnt,1);
				return NULL;
			}
			db_shutdown_msg->type = QUEUE_ITEM_TYPE_SHUTDOWN;
			db_shutdown_msg->data.db_op = NULL;
			if(enqueue(db_queue, db_shutdown_msg) != 0){
				fprintf(stderr,  "db shutdown msg send fail\n");
				free(db_shutdown_msg);
			}
			free(dequeued_item);
			// printf("No.%d worker thread shutdown\n", thread_num);
			break;
		}
		PacketInfo *pInfo = dequeued_item->data.packet_info;
		if(pInfo !=NULL){
			atomic_fetch_add(&global_stats->g_packet_cnt, 1);
			atomic_fetch_add(&global_stats->g_byte_cnt,pInfo->header.len);
			// packet parsing
			u_char *packet_data = pInfo->data;
			unsigned int caplen = pInfo->header.caplen;
			if(caplen >= sizeof(struct ethhdr)){
				struct ethhdr *eth_header = (struct ethhdr *)packet_data;
				unsigned short eth_type = ntohs(eth_header->h_proto);
				packet_data += sizeof(struct ethhdr);
				caplen -= sizeof(struct ethhdr);
				// ip header parsing, only ipv4
				if(eth_type==ETH_P_IP && caplen >= sizeof(struct iphdr)){
					struct iphdr *ip_header = (struct iphdr *)packet_data;
					unsigned int ip_header_len = ip_header->ihl*4;
					switch(ip_header->protocol){				
						case IPPROTO_TCP:
							if(caplen >= ip_header_len + sizeof(struct tcphdr)){
								atomic_fetch_add(&global_stats->tcp_stats.packet_cnt,1);
								atomic_fetch_add(&global_stats->tcp_stats.byte_cnt, pInfo->header.len);
								packet_data += ip_header_len;
								struct tcphdr *tcp_header = (struct tcphdr*)packet_data; 
								// http port check
								if(ntohs(tcp_header->source) == 80 || ntohs(tcp_header->dest) == 80){
									DBop *query_data = (DBop *)malloc(sizeof(DBop));
									if(query_data == NULL){
										fprintf(stderr," Failed to malloc db operation data\n");
										atomic_fetch_add(&global_stats->g_drop_cnt,1);
										free(pInfo);
										free(dequeued_item);
										continue;
									}
									if(makeMsg(query_data, pInfo, ip_header, tcp_header) == -1){
										// 실패했다면 호스트를 찾지 못한 것
										free(query_data);
										break;
									} else {
										atomic_fetch_add(&global_stats->detected_stats.packet_cnt, 1);
										atomic_fetch_add(&global_stats->detected_stats.byte_cnt, pInfo->header.len);
									}
									QueueMessage *item = (QueueMessage *)malloc(sizeof(QueueMessage));
									if(item == NULL){
										fprintf(stderr, "Failed to malloc QueueMessage(db)\n");
										continue;
									}
									item->type = QUEUE_ITEM_TYPE_DB_OP;
									item->data.db_op = query_data;
									if(enqueue(db_queue,item)!=0){
										fprintf(stderr, "enqueueing error\n");
										free(pInfo);
										free(item);
										free(query_data->matched_pattern);
										free(query_data);
										drop_flag = 1;
										break;
									}
								}				
							} else { 
								drop_flag = 1;
							}
							break;
						case IPPROTO_UDP:
							if(caplen >= ip_header_len + sizeof(struct udphdr)){
								atomic_fetch_add(&global_stats->udp_stats.packet_cnt,1);
								atomic_fetch_add(&global_stats->udp_stats.byte_cnt, pInfo->header.len);
							} else { 
								drop_flag = 1;
							}
							break;
						case IPPROTO_ICMP:
							if(caplen >= ip_header_len + sizeof(struct icmphdr)){
								atomic_fetch_add(&global_stats->icmp_stats.packet_cnt,1);
								atomic_fetch_add(&global_stats->icmp_stats.byte_cnt, pInfo->header.len);
							} else { 
								drop_flag = 1;
							}
							break;
						default:
							atomic_fetch_add(&global_stats->etc_stats.packet_cnt,1);
							atomic_fetch_add(&global_stats->etc_stats.byte_cnt, pInfo->header.len);
							break;
					}
					if(drop_flag == 1){
						drop_flag = 0;
						atomic_fetch_add(&global_stats->g_drop_cnt,1);
					}
				} else{
					atomic_fetch_add(&global_stats->etc_stats.packet_cnt,1);
					atomic_fetch_add(&global_stats->etc_stats.byte_cnt, pInfo->header.len);
				}
				free(pInfo);
			} else{
				atomic_fetch_add(&global_stats->g_drop_cnt,1);
			}
		}
		free(dequeued_item);
	}
	free(wti);
	return NULL;

}



int create_worker_thread(pthread_t *thread, MutexQueue *worker_queue, MutexQueue *db_queue ,GlobalStats *stats, int thread_num){
	int temp = 0;
	WorkerThreadInfo *wti = (WorkerThreadInfo *)malloc(sizeof(WorkerThreadInfo));
	if(wti == NULL){
		fprintf(stderr, "Failed to malloc for status\n");
	}
	wti->thread_num = (unsigned int)thread_num;
	wti->queue = worker_queue;
	wti->g_stats = stats;
	wti->db_queue = db_queue;
	if(pthread_create(thread, NULL, task_thread_work, (void *)wti)!=0){
		fprintf(stderr, "Failed to create woker thread\n");
		free(wti);
		return -1;
	}
	return 1;
}


void *db_thread_work(void *arg){
	time_t t = time(NULL);
	struct tm *time = localtime(&t);

	MutexQueue *queue = (MutexQueue *)arg;
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
			// printf("db thread received shutdown flag\n");
			db_get_signal = 1;
			// 버퍼에 남아있는 데이터 커밋
			int loop_cnt = queue->size;
			printf("remain exec : %d\n", loop_cnt);
			if(current_buffer_cnt > 0){
				if(begin_transaction()!= -1){
				for(int i = 0; i< loop_cnt; i++){
					if(insert_op(db_op_buffer[i])== -1){
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
			disconnect_db(); // db연결 해제
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
			memset(db_op_buffer, 0, sizeof(db_op_buffer)); // clean buffer
		}
	}
}


int create_db_thread(pthread_t *thread, MutexQueue *db_queue){
	if(pthread_create(thread, NULL, db_thread_work, (void *)db_queue) != 0){
		fprintf(stderr, "Failed to create db thread\n");
		return -1;
	}
	return 1;
}

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

	GlobalStats **all_thread_stats = print_args->all_thread_stats; // main스레드에서 해제
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
	args->thread_cnt = thread_cnt;
	if(pthread_create(thread, NULL, print_thread_work, (void*)args) != 0){
		fprintf(stderr, "Failed to create woker thread\n");
		free(args);
		return -1;
	}
	free(args);
	return 1;
}