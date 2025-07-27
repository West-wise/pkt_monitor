#include "thread_set.h"
#include "pattern.h"
#include "bm.h"
#include <inttypes.h>


#define DB_BATCH_SIZE 100
#define DB_BATCH_THRESHOLD ((DB_BATCH_SIZE*8)/10)

extern PatternList *g_pattern_list;
extern bmPattern **g_bm_patterns;
extern size_t g_bm_pattern_cnt;

void *task_thread_work(void *args){
        WorkerThreadInfo *wti = (WorkerThreadInfo*)args;
        int thread_num = wti->thread_num;
        MutexQueue *queue = wti->queue;
        MutexQueue *db_queue = wti->db_queue;
        GlobalStats *global_stats = wti->g_stats;
        while(1){
                QueueMessage *dequeued_item = dequeue(queue);
                // printf("Threa No.%d dequeued item!\n",thread_num);
                if(dequeued_item == NULL){
                        fprintf(stderr, "WThread No.%d dequeue error, drop packet\n", thread_num);
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
                                DBop *query_data = (DBop *)malloc(sizeof(DBop));
                                if(query_data == NULL){
                                        fprintf(stderr," Failed to malloc db operation data\n");
                                        
                                        free(pInfo);
                                        free(dequeued_item);
                                        return NULL;
                                }
                                query_data->time = pInfo->header.ts;

                                packet_data += sizeof(struct ethhdr);
                                caplen -= sizeof(struct ethhdr);

                                // ip header parsing, only ipv4
                                if(eth_type==ETH_P_IP && caplen >= sizeof(struct iphdr)){
                                        struct iphdr *ip_header = (struct iphdr *)packet_data;
                                        unsigned int ip_header_len = ip_header->ihl*4;
                                        unsigned int total_len_ip = ntohs(ip_header->tot_len);

                                        query_data->src_ip = ntohl(ip_header->saddr);
                                        query_data->dst_ip = ntohl(ip_header->daddr);
                                        query_data->protocol = ip_header->protocol;

                                        switch(ip_header->protocol){
                                                case IPPROTO_TCP:
                                                        if(caplen >= ip_header_len + sizeof(struct tcphdr)){
                                                                struct tcphdr *tcp_header = (struct tcphdr *)packet_data;
                                                                atomic_fetch_add(&global_stats->tcp_stats.packet_cnt,1);
                                                                atomic_fetch_add(&global_stats->tcp_stats.byte_cnt, pInfo->header.len);
                                                                query_data->src_port = ntohs(tcp_header->source);
                                                                query_data->dst_port = ntohs(tcp_header->dest);

                                                                // payload filter test
                                                                // 페이로드를 보려면 여기서 포트 확인해서 http면 까서 필터링을 하던
                                                                // 그런식으로 진행할 것.
                                                                // github에서 netfileter-1m했던것처럼

                                                        }
                                                        break;
                                                case IPPROTO_UDP:
                                                        if(caplen >= ip_header_len + sizeof(struct udphdr)){
                                                                struct udphdr *udp_header = (struct udphdr *)packet_data;
                                                                atomic_fetch_add(&global_stats->udp_stats.packet_cnt,1);
                                                                atomic_fetch_add(&global_stats->udp_stats.byte_cnt, pInfo->header.len);
                                                                query_data->src_port = ntohs(udp_header->source);
                                                                query_data->dst_port = ntohs(udp_header->dest);
                                                        }
                                                        break;
                                                case IPPROTO_ICMP:
                                                        if(caplen >= ip_header_len + sizeof(struct icmphdr)){
                                                                atomic_fetch_add(&global_stats->icmp_stats.packet_cnt,1);
                                                                atomic_fetch_add(&global_stats->icmp_stats.byte_cnt, pInfo->header.len);
                                                                query_data->src_port = 0;
                                                                query_data->dst_port = 0;
                                                        }
                                                        break;
                                                default:
                                                        atomic_fetch_add(&global_stats->etc_stats.packet_cnt,1);
                                                        atomic_fetch_add(&global_stats->etc_stats.byte_cnt, pInfo->header.len);
                                                        query_data->src_port = 0;
                                                        query_data->dst_port = 0;
                                                        break;

                                        }

                                 } else{
                                        atomic_fetch_add(&global_stats->etc_stats.packet_cnt,1);
                                        atomic_fetch_add(&global_stats->etc_stats.byte_cnt, pInfo->header.len);
                                        query_data->protocol = 0;
                                        query_data->src_ip = 0;
                                        query_data->dst_ip = 0;
                                        query_data->src_port = 0;
                                        query_data->dst_port = 0;
                                 }
                                // pattern processing



                                // enqueue
                                QueueMessage *item = (QueueMessage *)malloc(sizeof(QueueMessage));
                                if(item == NULL) {
                                       fprintf(stderr, "Failed to malloc QueueMessage(db)\n");
                                }
                                if(dequeued_item->type != QUEUE_ITEM_TYPE_SHUTDOWN){
                                        item->type = QUEUE_ITEM_TYPE_DB_OP;
                                }else{
                                        item->type = QUEUE_ITEM_TYPE_SHUTDOWN;
                                }

                                item->data.db_op = query_data;

                                if(enqueue(db_queue, item) != 0){
                                        fprintf(stderr, "eneueueing error\n");
                                        free(pInfo);
                                        free(item);
                                        free(dequeued_item);
                                        free(query_data);
                                        break;
                                }

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
                return -1;
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

        return 0;
}


void *db_thread_work(void *arg){
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
                DBop *op = deq_item->data.db_op;
                if(deq_item == NULL){
                        fprintf(stderr, "Failed to db item dequeue\n");
                        break;
                }

                if(deq_item->type == QUEUE_ITEM_TYPE_SHUTDOWN){
                        fprintf(stderr, "Received shotdown signal in db thread\n");
                        free(op);

                        if(current_buffer_cnt > 0){

                        }
                }
                if(current_buffer_cnt <= DB_BATCH_THRESHOLD){
                        db_op_buffer[current_buffer_cnt++] = op;
                } else{
                        if(begin_transaction()!= -1){
                                for(int i = 0; i<= DB_BATCH_SIZE; i++){
                                        if(insert_op(db_op_buffer[i])!= -1){
                                                free(db_op_buffer[i]);
                                        }
                                }
                                if(commit_transaction() != 0){
                                        rollback_transaction();
                                }
                        }

                }
                // printf("Protocol: %u\n", op->protocol);
                current_buffer_cnt = 0;
                memset(db_op_buffer, 0, sizeof(db_op_buffer)); // clean buffer
                free(op);
        }
}


int create_db_thread(pthread_t *thread, MutexQueue *db_queue){

        if(pthread_create(thread, NULL, db_thread_work, (void *)db_queue) != 0){
                fprintf(stderr, "Failed to create db thread\n");
                return -1;
        }

        return 1;
}


void *print_thread_work(void *args){
        PrintArgs *print_args = (PrintArgs*)args;

        if(print_args == NULL){
                fprintf(stderr, "printer job func received NULL\n");
                return NULL;
        }

        GlobalStats **all_thread_stats = print_args->all_thread_stats;

        int num = print_args->thread_cnt;
        unsigned int total_pps=0 , total_bps = 0, total_drop = 0;
        unsigned int t_tcp_pps = 0, t_tcp_bps = 0;
        unsigned int t_udp_pps = 0, t_udp_bps = 0;
        unsigned int t_icmp_pps = 0, t_icmp_bps = 0;
        unsigned int t_etc_pps = 0, t_etc_bps = 0;
        while(1){

                for(int k = 0; k<num; k++){
                        total_pps += atomic_exchange(&all_thread_stats[k]->g_packet_cnt,0);
                        total_bps += atomic_exchange(&all_thread_stats[k]->g_byte_cnt, 0);
                        total_drop += atomic_exchange(&all_thread_stats[k]->g_drop_cnt,0);

                        t_tcp_pps += atomic_exchange(&all_thread_stats[k]->tcp_stats.packet_cnt,0);
                        t_tcp_bps += atomic_exchange(&all_thread_stats[k]->tcp_stats.byte_cnt,0);

                        t_udp_pps += atomic_exchange(&all_thread_stats[k]->udp_stats.packet_cnt, 0);
                        t_udp_bps += atomic_exchange(&all_thread_stats[k]->udp_stats.byte_cnt, 0);

                        t_icmp_pps += atomic_exchange(&all_thread_stats[k]->icmp_stats.packet_cnt,0);
                        t_icmp_bps += atomic_exchange(&all_thread_stats[k]->icmp_stats.byte_cnt,0);

                        t_etc_pps += atomic_exchange(&all_thread_stats[k]->etc_stats.packet_cnt,0);
                        t_etc_bps += atomic_exchange(&all_thread_stats[k]->etc_stats.byte_cnt, 0);
                }
                printf("\n === Report(PPS/BPS) === \n");
                printf("Total:\n\tPPS: %u\n\tBPS: %u\n\tDROP: %u\n",total_pps, total_bps, total_drop); 
                printf("TCP:\n\tPPS: %u\n\tBPS: %u\n", t_tcp_pps, t_tcp_bps);
                printf("UDP:\n\tPPS: %u\n\tBPS: %u\n", t_udp_pps, t_udp_bps);
                printf("ICMP:\n\tPPS: %u\n\tBPS: %u\n", t_icmp_pps, t_icmp_bps);
                printf("ETC:\n\tPPS: %u\n\tBPS: %u\n", t_etc_pps, t_etc_bps);
                printf(" ====================== \n");
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

        return 1;
}

