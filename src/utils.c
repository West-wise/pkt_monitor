#include "utils.h"
#include "pattern.h"

extern PatternList *g_pattern_list;
extern bmPattern **g_bm_patterns;
extern size_t g_bm_pattern_cnt;

void usage(){
        fprintf(stderr, "\n\t\t\t[Usage]\n\n");
        fprintf(stderr, "General mode: \t\t./project1_psh -i <interface> -t <thread_cnt>\n");
        fprintf(stderr, "Advanced mode: \t\t./project1_psh -i <interface> -t <thread_cnt> -a <file_path>\n");
        fprintf(stderr, "PCAP analysis mode: \t./project1_psh -p <file_path>\n\n");
}

void handleSignal(int signal, siginfo_t *info, void *context){
        printf("Entered End of Process signal, exit program\n");
        pcap_t *handle = (pcap_t *)info->si_value.sival_ptr;
        printf("All Pcap handle closing..\n");
        if(handle != NULL){
                pcap_close(handle);
        }
        exit(0);
}

bool interface_check(const char *interface){
        if(interface == NULL){
                fprintf(stderr, "Interface name is NULL\n");
                return false;
        }
        pcap_if_t *alldevs;
        char errbuf[PCAP_ERRBUF_SIZE];
        if(pcap_findalldevs(&alldevs, errbuf) == -1){
                fprintf(stderr, "cannot find network interface\n\n");
                return false;
        }
        bool flag = false;
        for(pcap_if_t *dev = alldevs; dev != NULL; dev = dev->next){
                if(dev->name != NULL && strcmp(dev->name,interface) == 0){
                        flag = true;
                        break;
                }
        }
        if(!flag){
                fprintf(stderr, "Please Check interface name.\nValid Interface List: \n");
                int i = 1;
                for(pcap_if_t *dev = alldevs; dev != NULL; dev = dev->next){
                        if(dev->name != NULL && strstr(dev->name, "eth")){
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
                if(thread_cnt > 20){
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



int init_pattern(const char *file_path){
        g_pattern_list = load_patterns_from_file(file_path);
        if(g_pattern_list == NULL){
                fprintf(stderr, "failed to load file\n");
                return -1;
        }
        g_bm_patterns = (bmPattern **)malloc(sizeof(bmPattern *) * g_pattern_list->count);
        if(g_bm_patterns == NULL){
                fprintf(stderr, "Failed to malloc g_bm_pattern array\n");
                destroy_pattern_list(g_pattern_list);
                g_pattern_list = NULL;
                return -1;
        }

        g_bm_pattern_cnt = 0;

        for(size_t i = 0; i<g_pattern_list->count; i++){
                PatternRule *rule = &g_pattern_list->rules[i];
                bmPattern *bm_p = bm_process_pattern(rule->value_str);
                if(bm_p == NULL){
                        fprintf(stderr, "Failed to preprocess pattern\n");
                } else{
                        g_bm_patterns[g_bm_pattern_cnt++] = bm_p;
                }
        }
        return 0;
}


void pattern_cleanup(){

        if(g_bm_patterns != NULL){
                for(size_t i = 0; i< g_bm_pattern_cnt; i++){
                        bm_destroy_pattern(g_bm_patterns[i]);
                }
                free(g_bm_patterns);
                g_bm_patterns = NULL;
                g_bm_pattern_cnt = 0;
        }
        if(g_pattern_list != NULL){
                destroy_pattern_list(g_pattern_list);
                g_pattern_list = NULL;
        }
}


void print_hex_dump(const u_char *data_ptr, unsigned int len, unsigned int offset_start) {
    unsigned int i, j;
    const int BYTES_PER_LINE = 16; // 한 줄에 출력할 바이트 수

    if (data_ptr == NULL || len == 0) {
        printf("No data to dump.\n");
        return;
    }

    printf("--- Hex Dump (Length: %u bytes) ---\n", len);

    for (i = 0; i < len; i += BYTES_PER_LINE) {
        // 1. 오프셋 출력 (예: 0000, 0010, ...)
        printf("%04x: ", offset_start + i);

        // 2. 16진수 값 출력
        for (j = 0; j < BYTES_PER_LINE; j++) {
            if (i + j < len) {
                printf("%02x ", data_ptr[i + j]);
            } else {
                // 데이터 끝에 도달하면 공백으로 채워 정렬 유지
                printf("   ");
            }
            if (j == 7) { // 8바이트마다 추가 공백으로 가독성 향상
                printf(" ");
            }
        }

        // 3. ASCII 문자 출력
        printf("  "); // 16진수와 ASCII 사이의 공백
        for (j = 0; j < BYTES_PER_LINE; j++) {
            if (i + j < len) {
                // 출력 가능한 ASCII 문자는 그대로 출력, 아니면 '.' 출력
                if (isprint(data_ptr[i + j])) {
                    putchar(data_ptr[i + j]);
                } else {
                    putchar('.');
                }
            }
        }
        printf("\n"); // 한 줄 끝
    }
    printf("----------------------------------\n");
}
