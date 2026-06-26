#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

#define BUFFER_SIZE 65536
#define RULES_FILE "rules.txt"
#define LOG_FILE "firewall_alerts.log"
#define MAX_BANNED_IPS 100
#define MAX_LOG_SIZE 5242880 // 5 Megabytes in bytes

char banned_ips[MAX_BANNED_IPS][32];
int banned_ip_count = 0;

void check_and_rotate_logs() {
    struct stat st;
    // Check if file exists and get status
    if (stat(LOG_FILE, &st) == 0) {
        if (st.st_size >= MAX_LOG_SIZE) {
            printf("[!] Log threshold reached (%ld bytes). Executing automatic rotation/reset...\n", st.st_size);
            
            // For simplicity in a single-file setup, we clear the file to prevent overflow.
            // In full enterprise tools, you would rename this to .old and open a new one.
            FILE *clear_file = fopen(LOG_FILE, "w");
            if (clear_file) {
                fprintf(clear_file, "[%ld] --- LOG BUFFER AUTOMATICALLY RESET TO PREVENT HARD DRIVE OVERFLOW ---\n", (long)time(NULL));
                fclose(clear_file);
                printf("[*] Forensic log space successfully reclaimed.\n");
            }
        }
    }
}

void log_firewall_incident(const char* src_ip, int src_port, int dest_port, const char* flag_state, int size) {
    // Check size limitations before making an append write
    check_and_rotate_logs();

    FILE *log = fopen(LOG_FILE, "a");
    if (log) {
        time_t now = time(NULL);
        char *time_str = ctime(&now);
        time_str[strlen(time_str) - 1] = '\0'; 

        fprintf(log, "[%s] ALERT | Source: %s:%d -> Local:%d | State: %s | Size: %d Bytes\n", 
                time_str, src_ip, src_port, dest_port, flag_state, size);
        fclose(log);
    }
}

void load_firewall_rules() {
    FILE *file = fopen(RULES_FILE, "r");
    if (!file) {
        printf("[!] Warning: Configuration '%s' not found. Running with empty ruleset.\n", RULES_FILE);
        return;
    }

    banned_ip_count = 0;
    while (fgets(banned_ips[banned_ip_count], 32, file) && banned_ip_count < MAX_BANNED_IPS) {
        banned_ips[banned_ip_count][strcspn(banned_ips[banned_ip_count], "\r\n")] = '\0';
        if (strlen(banned_ips[banned_ip_count]) > 0) {
            printf("[RULE LOADED] Blacklisted IP: %s\n", banned_ips[banned_ip_count]);
            banned_ip_count++;
        }
    }
    fclose(file);
    printf("[*] Successfully loaded %d threat signatures into memory.\n", banned_ip_count);
}

void process_packet(unsigned char* buffer, int size) {
    struct iphdr *iph = (struct iphdr*)buffer;
    
    if (iph->protocol == 6) { 
        struct sockaddr_in source, dest;
        memset(&source, 0, sizeof(source));
        memset(&dest, 0, sizeof(dest));
        
        source.sin_addr.s_addr = iph->saddr;
        dest.sin_addr.s_addr = iph->daddr;
        
        char src_ip[32];
        strcpy(src_ip, inet_ntoa(source.sin_addr));
        
        int ip_header_len = iph->ihl * 4;
        struct tcphdr *tcph = (struct tcphdr*)(buffer + ip_header_len);
        
        int src_port = ntohs(tcph->source);
        int dest_port = ntohs(tcph->dest);

        for (int i = 0; i < banned_ip_count; i++) {
            if (strcmp(src_ip, banned_ips[i]) == 0) {
                char flag_desc[64] = "DATA_TRANSMISSION";
                
                if (tcph->syn && !tcph->ack) {
                    strcpy(flag_desc, "UNAUTHORIZED_SYN_ATTEMPT");
                } else if (tcph->rst) {
                    strcpy(flag_desc, "CONNECTION_RESET_RST");
                } else if (tcph->fin) {
                    strcpy(flag_desc, "CONNECTION_TERMINATION_FIN");
                }

                printf("\n🚨 [FIREWALL INCIDENT] Intercepted Blacklisted Host [%s] -> Logged to Disk\n", src_ip);
                
                log_firewall_incident(src_ip, src_port, dest_port, flag_desc, size);
                break;
            }
        }
    }
}

int main() {
    int sock_raw;
    struct sockaddr_in saddr;
    unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE); 

    printf("====================================================\n");
    printf("   LAUNCHING SELF-ROTATING IPS FIREWALL ENGINE       \n");
    printf("====================================================\n");
    
    load_firewall_rules();
    
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw < 0) {
        perror("Socket initialization failed. Run via 'sudo'");
        free(buffer);
        return 1;
    }

    printf("\n[*] Processing active. Monitoring socket streams...\n");

    while (1) {
        int saddr_size = sizeof(saddr);
        int data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&saddr, (socklen_t*)&saddr_size);
        if (data_size < 0) {
            perror("Data collection stream breakdown");
            free(buffer);
            close(sock_raw);
            return 1;
        }
        
        process_packet(buffer, data_size);
    }

    close(sock_raw);
    free(buffer);
    return 0;
}
