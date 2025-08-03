#define _GNU_SOURCE
#include <pcap.h>

#include "common.h"
#include "utils.h"
#include "thread_set.h"
#include "queue_set.h"
#include "trie.h"

#define QUEUE_SIZE 1024

TrieNode *trie = NULL;
sig_atomic_t sig_stop = 0;

void handleSignal(int signal, siginfo_t *info, void *context){
	sig_stop = 1;
}

void send_shutdown_msg_all_queue(u_char *user_data){
	// printf("sending shutdown flag\n");
	PcapHandlerArgs *args = (PcapHandlerArgs *)user_data;

	for(int i = 0; i<args->num_queues; i++){
		MutexQueue *target_queue = getQueue(args->queue_list, i);
		QueueMessage *item = (QueueMessage *)malloc(sizeof(QueueMessage));
		if(item == NULL){
			fprintf(stderr, "Failed to malloc QueueMsg for shutdown\n");
			return;
		}
		item->type = QUEUE_ITEM_TYPE_SHUTDOWN;
		item->data.packet_info = NULL;
		if(enqueue(target_queue, item) != 0){
			fprintf(stderr, "shutdown msg enqueueing err\n");
			free(item);
			return;
		}
	}
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

	if(user_data == NULL){
		fprintf(stderr, "packet_handler received NULL data\n");
		return;
	}
	if(sig_stop == 1){
		printf("ramain packet processing..\n");
	}
	PcapHandlerArgs *args = (PcapHandlerArgs *)user_data;
	// 일단 테스트 용으로 인덱스만 순환
	args->current_queue_id = (args->current_queue_id + 1) % args->num_queues;
	MutexQueue *target_queue = getQueue(args->queue_list, args->current_queue_id);
	GlobalStats *stats = (args->handler_stats);
	if(target_queue == NULL){
		fprintf(stderr, "error occured in get queue\n");
		return;
	}
	QueueMessage *item = (QueueMessage *)malloc(sizeof(QueueMessage));
	if(item == NULL){
		fprintf(stderr, "Failed to malloc QueueMessage\n");
		atomic_fetch_add(&stats->g_drop_cnt,1);
		return;
	}

	item->type = QUEUE_ITEM_TYPE_PACKET_INFO;
	PacketInfo *pInfo = (PacketInfo *)malloc(sizeof(PacketInfo) + pkthdr->caplen);
	if(pInfo == NULL){
		fprintf(stderr, "Failed to malloc PacketInfo\n");
		atomic_fetch_add(&stats->g_drop_cnt,1);
		free(item);
		return;
	}
	pInfo->header = *pkthdr;
	memcpy(pInfo->data, packet, pkthdr->caplen);

	item->data.packet_info = pInfo;

	if(enqueue(target_queue, item)!= 0){
		fprintf(stderr, "enqueueing error\n");
		atomic_fetch_add(&stats->g_drop_cnt,1);
		free(pInfo);
		free(item);
		return;
	}
}



int main(int argc, char *argv[]){
        char *interface = NULL;
        int thread_cnt = 1;
        char *pattern_file_path = NULL;
        char *pcap_file_path = NULL;
		int packet_handler_stat_idx = 0;
		int db_stat_idx = 0;
        int opt;
        int mode = 1; // 0: Undefine, 1: Advance, 3: pcap analysis
        while((opt = getopt(argc, argv, "i:t:a:p:h")) != -1){
			switch(opt){
					case 'i':
							interface = optarg;
							break;
					case 't':
							thread_cnt = atoi(optarg);
							packet_handler_stat_idx = thread_cnt + 1;
							db_stat_idx = thread_cnt + 2;
							break;
					case 'a':
							pattern_file_path = optarg;
							break;
					case 'p':
							pcap_file_path = optarg;
							mode = 2;
							break;
					default:
							usage();
							return -1;
				}
		}
	if(!interface_check(interface)){
		return -1;	
	}
	if(mode_check(mode, interface, thread_cnt, pattern_file_path, pcap_file_path)==-1){
		return -1;
	}


	//pattern preprocessing
	trie = createNode();
	if(triePreprocess(pattern_file_path, trie) != 0){
		fprintf(stderr, "Failed to init pattern\n");
		freeTrie(trie);
		return -1;
	}else{
		printf("trie created\n");
	}
	pthread_t db_thread, printer_thread;
	pthread_t workers[thread_cnt];
	MutexQueue *db_queue = (MutexQueue*)malloc(sizeof(MutexQueue));
	if(db_queue == NULL){
		fprintf(stderr, "Failed to malloc db_queue\n\n");
		return -1;
	}
	initQueue(db_queue, QUEUE_SIZE);
	MutexQueueList *worker_queue_list = createQueueList(thread_cnt);

	GlobalStats **all_stats = (GlobalStats **)malloc(sizeof(GlobalStats *) * (thread_cnt + 2)); // thread + db + packet_handler
 	if(all_stats==NULL){
		fprintf(stderr, "Failed to malloc every stats\n");
		return -1;
	}
	for(int i = 0; i<thread_cnt + 2; i++){
		all_stats[i] = (GlobalStats *)malloc(sizeof(GlobalStats));
		if(all_stats[i] == NULL){
			fprintf(stderr, "Failed to malloc No.%d stats\n", i);
			continue;
		}
		atomic_init_func(all_stats[i]);
	}

	DBThreadInfo *db_info = (DBThreadInfo *)malloc(sizeof(DBThreadInfo));
	db_info->queue = db_queue;
	db_info->stat = all_stats[db_stat_idx];

	// thread create
	//
	if(create_db_thread(&db_thread, db_info) == -1){
		fprintf(stderr, "creating Database thread failed...\n");
		return -1;
	}

	for(int i = 0; i<thread_cnt; i++){
		atomic_init_func(all_stats[i]);
		if(all_stats[i] == NULL){
			fprintf(stderr, "No.%d stat is NULL. So, No.%d worker thread create cancle\n", i, i);
			continue;
		}
		if(create_worker_thread(&workers[i], getQueue(worker_queue_list, i), db_queue, all_stats[i],i+1) == -1){
			fprintf(stderr, "Failed to create No.%d worker thread\n\n",i);
			free(all_stats[i]);
			return -1;
		}		
	}

	if(create_printer_thread(&printer_thread, all_stats, thread_cnt) == -1){
		fprintf(stderr, "creating printer thread failed\n");
		return -1;
	}

	
	

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct pcap_stat stats;
	if(mode == 1){
		handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
		if(handle == NULL){
			fprintf(stderr, "Failed to open live handle\n");
			return -1;
		} else{
			printf("live handle open success\n");
		}

		if (pcap_setnonblock(handle, 1, errbuf) == -1) {  // 1: non-blocking 모드 활성화
			fprintf(stderr, "Failed to set nonblock: %s\n", errbuf);
			pcap_close(handle);
			return -1;
		}

	} else {
		handle =pcap_open_offline(pcap_file_path, errbuf);
		if(handle == NULL){
			fprintf(stderr, "[-] pcap_open_offline failed: %s\n", errbuf);
		}else{
			printf("pcap_open_offline success\n");
		}
	}


	// set exit signal
	struct sigaction sa;
	sa.sa_flags = SA_SIGINFO | SA_RESTART;
	sa.sa_sigaction = handleSignal;
	sigemptyset(&sa.sa_mask);
	
	union sigval val;
	val.sival_ptr = handle;

	if(sigaction(SIGINT, &sa, NULL) == -1){
		perror("sigcation(SIGINT) failed");
		if(handle) pcap_close(handle);
		return 1;
	}

	if(sigaction(SIGTERM, &sa, NULL) == -1){
		perror("sigaction(SIGTERM) failed\n");
		if(handle) pcap_close(handle);
		return 1;
	}

	if(sigaction(SIGQUIT, &sa, NULL) == -1){
		perror("sigaction(SIGQUIT) failed\n");
		if(handle) pcap_close(handle);
		return 1;
	}

	// make struct for packet handler
	PcapHandlerArgs *pArgs = (PcapHandlerArgs*)malloc(sizeof(PcapHandlerArgs));
	if(pArgs==NULL){
		fprintf(stderr, "Failed to malloc pArgs\n");
	}
	pArgs->queue_list = worker_queue_list;
	pArgs->num_queues = thread_cnt;
	pArgs->current_queue_id = 0;
	pArgs->handler_stats = all_stats[packet_handler_stat_idx];

	struct pcap_pkthdr *header; // packet header pointer
	const u_char *packet; // packet data pointer
	int res;
	// changing to pcap_next_ex
	int flag = 0;
	int drop_cnt = 0;

	sig_atomic_t expected = 0;
	sig_atomic_t desired = 1;
	
	while(1){
		if(sig_stop == 1){
			fprintf(stderr, "Received SIGNAL\n");
			int remain_packet = pcap_dispatch(handle,0,(pcap_handler)packet_handler, (u_char*)pArgs);
			sleep(2); // 잔여 패킷 처리를 위한 sleep설정
			if(remain_packet > 0){
				printf("buffer consumed\n");
				printf("remained packet : %d\n", remain_packet);
			} else if(remain_packet == -1){
				fprintf(stderr, "ERROR : %s\n", pcap_geterr(handle));
			} else if(remain_packet == -2){
				fprintf(stderr, "BREAK : %s\n", pcap_geterr(handle));
			}
			break;
		}
		if(handle == NULL) fprintf(stderr, "handle is null\n");
		// res = pcap_next_ex(handle, &header, &packet);
		res = pcap_next_ex(handle, &header, &packet);
		switch(res){
			case 0: //timeout
				// printf("pcap timeout, waiting....\n");
				break;
			case 1: // success
				packet_handler((u_char*)pArgs, header, packet);
				break;
			case PCAP_ERROR:
				fprintf(stderr, "pcap error No.%d : %s\n", res, pcap_geterr(handle));
				flag = 1;
				drop_cnt++;
				break;
			case PCAP_ERROR_BREAK:
				if(mode == 2){
					// printf("File read done\n");
				} else{
					fprintf(stderr, "pcap error break No.%d : %s\n", res, pcap_geterr(handle));
				}
				flag = 1;
				drop_cnt++;
				break;
			default:
				fprintf(stderr,"Another pcap error received\n");
				break;
		}
		if(flag == 1) break;
	}
	
	if(mode==2){
		sleep(1);
	}
	send_shutdown_msg_all_queue((u_char*)pArgs);
	
	for(int i = 0; i<thread_cnt; i++){
		if(pthread_join(workers[i],NULL) != 0){
			printf("No.%d worker thread join failed\n", i);
		}
	}
	if(pthread_join(db_thread,NULL)!=0){
		printf("DB Thread join failed\n");
	}
	if(pthread_join(printer_thread, NULL) != 0){
		printf("Printer Thread join failed\n");
	}
	freeTrie(trie);
	free(pArgs);
	destroyQueue(db_queue);
	free(db_queue);
	free(db_info);
	destroyQueueList(worker_queue_list);
	

	if(all_stats != NULL){
		for(int i = 0; i<thread_cnt + 2; i++){
			if(all_stats[i] != NULL){
				free(all_stats[i]);
				all_stats[i] = NULL;
			}
		}
		free(all_stats);
	}
	// if(pcap_stats(handle, &stats)== -1){
	// 	fprintf(stderr, "Error : %s\n", pcap_geterr(handle));
	// 	pcap_close(handle);
	// 	return 0;
	// }
	
	// printf("\n--- pcap_stats --- \n");
    // printf("Packets received by filter: %u\n", stats.ps_recv);
    // printf("Packets dropped by kernel:  %u\n", stats.ps_drop);
    // printf("Packets dropped by interface: %u\n", stats.ps_ifdrop);
    // printf("--------------------\n");

	
	pcap_close(handle);
	return 0;
}
