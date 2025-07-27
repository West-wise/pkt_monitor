#include <pcap.h>
#include "utils.h"


#define QUEUE_SIZE 1024

PatternList *g_pattern_list = NULL;
bmPattern **g_bm_patterns = NULL;
size_t g_bm_pattern_cnt = 0;



void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

        if(user_data == NULL){
                fprintf(stderr, "packet_handler received NULL data\n");
                return;
        }
        PcapHandlerArgs *args = (PcapHandlerArgs *)user_data;
        // 일단 테스트 용으로 인덱스만 순환
        args->current_queue_id = (args->current_queue_id + 1) % args->num_queues;
        MutexQueue *target_queue = getQueue(args->queue_list, args->current_queue_id);
        if(target_queue == NULL){
                fprintf(stderr, "error occured in get queue\n");
                return;
        }
        QueueMessage *item = (QueueMessage *)malloc(sizeof(QueueMessage));
        if(item == NULL){
                fprintf(stderr, "Failed to malloc QueueMessage\n");
                return;
        }

        item->type = QUEUE_ITEM_TYPE_PACKET_INFO;
        PacketInfo *pInfo = (PacketInfo *)malloc(sizeof(PacketInfo) + pkthdr->caplen);
        if(pInfo == NULL){
                fprintf(stderr, "Failed to malloc PacketInfo\n");
                free(item);
                return;
        }
        pInfo->header = *pkthdr;
        memcpy(pInfo->data, packet, pkthdr->caplen);

        item->data.packet_info = pInfo;

        if(enqueue(target_queue, item)!= 0){
                fprintf(stderr, "enqueueing error\n");
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
        int opt;
        int mode = 1; // 0: Undefine, 1: Advance, 3: pcap analysis
        while((opt = getopt(argc, argv, "i:t:a:p:h")) != -1){
                switch(opt){
                        case 'i':
                                interface = optarg;
                                break;
                        case 't':
                                thread_cnt = atoi(optarg);
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

        // pattern preprocessing
        if(init_pattern(pattern_file_path) != 0){
                fprintf(stderr, "Failed to initialized pattern\n");
                pattern_cleanup();
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

        // thread create
        //
        if(create_db_thread(&db_thread, db_queue) == -1){
                fprintf(stderr, "creating Database thread failed...\n");
                return -1;
        }


        GlobalStats **all_stats = (GlobalStats **)malloc(sizeof(GlobalStats *) * thread_cnt);
        if(all_stats==NULL){
                fprintf(stderr, "Failed to malloc every stats\n");
                return -1;
        }

        for(int i = 0; i<thread_cnt; i++){
                all_stats[i] = (GlobalStats *)malloc(sizeof(GlobalStats));
                if(all_stats[i] == NULL){
                        fprintf(stderr, "Failed to malloc single stats\n");
                        free(all_stats[i]);
                        return -1;
                }
                atomic_init_func(all_stats[i]);
                if(create_worker_thread(&workers[i], getQueue(worker_queue_list, i), db_queue, all_stats[i],i+1) == -1){
                        fprintf(stderr, "Failed to create No.%d worker thread\n\n",i);
                        for(int k=0; k<i; k++) free(all_stats[k]);
                        free(all_stats);
                        return -1;
                }

        }
        if(create_printer_thread(&printer_thread, all_stats, thread_cnt) == -1){
                fprintf(stderr, "creating printer thread failed\n");
                return -1;
        }



        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle;
        if(mode == 1){
                handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf); //1000 수치 조정 필요
        } else if(mode == 2){
                handle =pcap_open_offline(pcap_file_path, errbuf);
                if(handle == NULL){
                        fprintf(stderr, "[-] pcap_open_offline failed: %s\n", errbuf);
                }else{
                        printf("pcap_open_offline success\n");
                }
        }

        // set exit signal
        struct sigaction sa;
        sa.sa_sigaction = handleSignal;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);

        union sigval val;
        val.sival_ptr = handle;

        if(sigaction(SIGINT, &sa, NULL) == -1){
                perror("sigcation failed");
                pcap_close(handle);
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


        printf("Capturing....\n");

        if(pcap_loop(handle, 0, packet_handler,(u_char *)pArgs) < 0) {
                fprintf(stderr, "[-] pcap_loop failed: %s\n", pcap_geterr(handle));
                pcap_close(handle);
                return EXIT_FAILURE;
        } 


        if(mode == 2){
                sleep(1);
        }
        
        pthread_join(db_thread, NULL);
        pthread_join(printer_thread,NULL);
        for(int i =0; i<thread_cnt; i++){
                pthread_join(workers[i], NULL);
        }
        if(pArgs != NULL){
                free(pArgs);
                pArgs=NULL;
        }
        pattern_cleanup();
        free(worker_queue_list);


        if (all_stats != NULL) {
                for (int i = 0; i < thread_cnt; i++) {
                        if (all_stats[i] != NULL) {
                        free(all_stats[i]);
                        all_stats[i] = NULL;
                        }
                }
                free(all_stats);
                all_stats = NULL;
        }


        pcap_close(handle);
        return 0;
}