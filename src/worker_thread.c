#define _GNU_SOURCE
#include "worker_thread.h"
#include <inttypes.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <pcap/pcap.h>
#include <string.h>
#include <unistd.h>

#include "trie.h"
#include "log_db.h"

#define UDS_PATH "/home/phob/Desktop/snort/snort.sock"

extern TrieNode *trie;
extern sig_atomic_t db_get_signal;

int send_packet(int client_fd, const struct pcap_pkthdr *hdr, const u_char *packet) {
    if (client_fd < 0 || hdr == NULL || packet == NULL) {
        return -1; // null check
    }

    struct iovec iov[2];
    iov[0].iov_base = (void *)hdr;
    iov[0].iov_len  = sizeof(struct pcap_pkthdr);
    iov[1].iov_base = (void *)packet;
    iov[1].iov_len  = hdr->caplen;

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov    = iov;
    msg.msg_iovlen = 2;

    ssize_t sent = sendmsg(client_fd, &msg, 0);
    if (sent == -1) {
        perror("sendmsg");
        return -1;
    }

    return 0;
}


int makeMsg(DBop *query_data, PacketInfo *pInfo, struct iphdr *ip_header, struct tcphdr *tcp_header){
	query_data->time = pInfo->header.ts;
	query_data->protocol = ip_header->protocol;
	query_data->src_ip = ip_header->saddr;
	query_data->src_port = ntohs(tcp_header->source);
	query_data->dst_ip = ip_header->daddr;
	query_data->dst_port = ntohs(tcp_header->dest);

	const char *http_payload = (char *)tcp_header + (tcp_header->doff*4);
	size_t payload_len = ntohs(ip_header->tot_len) - (ip_header->ihl*4) - (tcp_header->doff*4);
	const char *host_header = memmem(http_payload, payload_len, "Host: ", 6);
	if(host_header){
		host_header += 6; // "Host: " length
		const char *eol = strchr(host_header, '\r');
		if(eol){
			char host[100];
			size_t hostname_len = eol - host_header;
			snprintf(host, sizeof(host), "%.*s",(int)hostname_len, host_header);
			if(find(trie, host) == 0){
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

    // --- [추가] UDS 클라이언트 소켓 연결 ---
    int client_fd;
    struct sockaddr_un addr;

    client_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (client_fd < 0) {
        perror("socket");
        free(wti);
        return NULL;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, UDS_PATH, sizeof(addr.sun_path) - 1);

    if (connect(client_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(client_fd);
        free(wti);
        return NULL;
    }

    printf("[Worker %d] Connected to UDS server (%s)\n", thread_num, UDS_PATH);
    // -------------------------------------

    while(1){
        QueueMessage *dequeued_item = dequeue(queue);
        if(dequeued_item == NULL){
            fprintf(stderr, "Worker Thread No.%d dequeue error, drop packet\n", thread_num);
            continue;
        }
        if(dequeued_item->type == QUEUE_ITEM_TYPE_SHUTDOWN){
            if(!atomic_compare_exchange_strong(&db_get_signal,&expected,desired)){
                free(dequeued_item);
                break;
            }

            QueueMessage *db_shutdown_msg = (QueueMessage *)malloc(sizeof(QueueMessage));
            if(db_shutdown_msg == NULL){
                fprintf(stderr, "Failed to malloc db_shutdown msg\n");
                free(dequeued_item);
                atomic_fetch_add(&global_stats->g_drop_cnt,1);
                close(client_fd);   // [추가] 소켓 닫기
                return NULL;
            }
            db_shutdown_msg->type = QUEUE_ITEM_TYPE_SHUTDOWN;
            db_shutdown_msg->data.db_op = NULL;
            if(enqueue(db_queue, db_shutdown_msg) != 0){
                fprintf(stderr,  "db shutdown msg send fail\n");
                free(db_shutdown_msg);
            }
            free(dequeued_item);
            break;
        }

        PacketInfo *pInfo = dequeued_item->data.packet_info;
        if(pInfo !=NULL){
            atomic_fetch_add(&global_stats->g_packet_cnt, 1);
            atomic_fetch_add(&global_stats->g_byte_cnt,pInfo->header.len);
            u_char *packet_data = pInfo->data;
            unsigned int caplen = pInfo->header.caplen;

            if(caplen >= sizeof(struct ethhdr)){
                struct ethhdr *eth_header = (struct ethhdr *)packet_data;
                unsigned short eth_type = ntohs(eth_header->h_proto);
                packet_data += sizeof(struct ethhdr);
                caplen -= sizeof(struct ethhdr);

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
                                        free(query_data);
                                        continue; // 메모리 릭 방지
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

                // --- [추가] UDS 전송 ---
                struct iovec iov[2];
                iov[0].iov_base = &(pInfo->header);
                iov[0].iov_len  = sizeof(struct pcap_pkthdr);
                iov[1].iov_base = pInfo->data;
                iov[1].iov_len  = pInfo->header.caplen;

                struct msghdr msg;
                memset(&msg, 0, sizeof(msg));
                msg.msg_iov = iov;
                msg.msg_iovlen = 2;

                ssize_t sent = sendmsg(client_fd, &msg, 0);
                if(sent < 0){
                    fprintf(stderr, "[Worker %d] sendmsg error: %s\n", thread_num, strerror(errno));
                } else {
                    // printf("[Worker %d] Sent packet len=%d\n", thread_num, pInfo->header.caplen);
                }
                // ----------------------

                free(pInfo);
            } else{
                atomic_fetch_add(&global_stats->g_drop_cnt,1);
            }
        }
        free(dequeued_item);
    }

    close(client_fd);   // [추가] 종료 시 소켓 닫기
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
