#include "utils.h"

#define THREAD_CNT 2000

void usage(){
        fprintf(stderr, "\n\t\t\t[Usage]\n\n");
        fprintf(stderr, "General mode: \t\t./project1_psh -i <interface> -t <thread_cnt>\n");
        fprintf(stderr, "Advanced mode: \t\t./project1_psh -i <interface> -t <thread_cnt> -a <file_path>\n");
        fprintf(stderr, "PCAP analysis mode: \t./project1_psh -p <file_path>\n\n");
}

/* void handleSignal(int signal, siginfo_t *info, void *context){
	

} */

bool interface_check(const char *interface){
        pcap_if_t *alldevs = NULL;
        char errbuf[PCAP_ERRBUF_SIZE] = {0,};
        if(pcap_findalldevs(&alldevs, errbuf) == -1){
	        fprintf(stderr, "cannot find network interface\n\n");
	        return false;
	}
        bool flag = false;
        for(pcap_if_t *dev = alldevs; dev != NULL; dev = dev->next){
                if(strcmp(dev->name,interface) == 0){
                        flag = true;
                        break;
                }
        }
        if(!flag){
                fprintf(stderr, "Please Check interface name.\nValid Interface List: \n");
                int i = 1;
                for(pcap_if_t *dev = alldevs; dev != NULL; dev = dev->next){
			if(strstr(dev->name, "eth")){
                                printf("%d. %s\n", i++, dev->name);
                        }
                }
        }
        pcap_freealldevs(alldevs);
        return flag;
}


int mode_check(int mode, char *interface, int thread_cnt, char *advanced_file_path, char *pcap_file_path){

	if(mode == 2 ){
 	       if(pcap_file_path == NULL){
	               fprintf(stderr, "ERROR: pcap file path required");
	               usage();
	               return -1;
		}
	printf("\n\t\t\t[PCAP File Analysis Mode]\n\n");
	printf("  File Path: \t%s\n\n", pcap_file_path);
	} else {
	        if(interface == NULL || thread_cnt <= 0) {
	                fprintf(stderr, "ERROR: interface or thread cnt are required");
	                usage();
	                return -1;
	        }
	        if(thread_cnt > THREAD_CNT){
	                fprintf(stderr, "WARN: thread is too many!\n");
	                return -1;
	        }
	        if(mode == 1){
	                if(advanced_file_path == NULL){
	                        fprintf(stderr, "ERROR pattern file path is required");
	                        usage();
	                        return -1;
	        }
			printf("\n\t\t\t[Live Mode]\n\n");
			printf("Interface\t\t: \t%s\n", interface);
			printf("Number of Threads\t: \t%d\n", thread_cnt);
			printf("Pattern File Path: \t%s\n\n", advanced_file_path);
            }
        }
	return 0;
}



void atomic_init_func(GlobalStats *g_stats){

	atomic_init(&g_stats->g_packet_cnt,0);
	atomic_init(&g_stats->g_byte_cnt, 0);
	atomic_init(&g_stats->g_drop_cnt, 0);
	
	atomic_init(&g_stats->tcp_stats.packet_cnt, 0);
	atomic_init(&g_stats->tcp_stats.byte_cnt, 0);
	atomic_init(&g_stats->udp_stats.packet_cnt, 0);
	atomic_init(&g_stats->udp_stats.byte_cnt, 0);
	atomic_init(&g_stats->icmp_stats.packet_cnt, 0);
	atomic_init(&g_stats->icmp_stats.byte_cnt, 0);
	atomic_init(&g_stats->etc_stats.packet_cnt, 0);
	atomic_init(&g_stats->etc_stats.byte_cnt, 0);
}




