#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

#define BUFFER_SIZE 65536
#define RULES_FILE "rules.txt"
#define MAX_BANNED_IPS 100

char banned_ips[MAX_BANNED_IPS][32];
int banned_ip_count = 0;

// Reads the blacklist rules from the external configuration file
void load_firewall_rules() {
    FILE *file = fopen(RULES_FILE, "r");
    if (!file) {
        printf("[!] Warning: Configuration '%s' not found. Running with empty ruleset.\n", RULES_FILE);
        return;
    }

    banned_ip_count = 0;
    while (fgets(banned_ips[banned_ip_count], 32, file) && banned_ip_count < MAX_BANNED_IPS) {
        // Strip trailing newline character if present
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
    
    if (iph->protocol == 6) { // TCP Protocol
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

        // Scan internal memory rules array for a source IP match
        for (int i = 0; i < banned_ip_count; i++) {
            if (strcmp(src_ip, banned_ips[i]) == 0) {
                printf("\n🚨 [DYNAMIC FIREWALL ALERT] Intercepted Blacklisted Host [%s]\n", src_ip);
                printf("| Target Port: %d -> Local Port: %d | Size: %d Bytes\n", src_port, dest_port, size);
                
                if (tcph->syn && !tcph->ack) {
                    printf("| State: Unauthorized [SYN] Connection Request!\n");
                } else if (tcph->rst) {
                    printf("| State: Connection Reset [RST] Detected.\n");
                } else {
                    printf("| State: Active Transmission Payload Blocks Detected.\n");
                }
                printf("------------------------------------------------------------------\n");
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
    printf("   LAUNCHING DYNAMIC CONFIGURATION FIREWALL IPS     \n");
    printf("====================================================\n");
    
    load_firewall_rules();
    
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw < 0) {
        perror("Socket initialization failed. Run via 'sudo'");
        free(buffer);
        return 1;
    }

    printf("\n[*] Packet evaluation core live. Monitoring network interface traffic...\n");

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
