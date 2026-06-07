#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

#define BUFFER_SIZE 65536

// Define the target IP address you want to monitor or block
#define BANNED_IP "142.250.206.174"

void process_packet(unsigned char* buffer, int size) {
    struct iphdr *iph = (struct iphdr*)buffer;
    
    if (iph->protocol == 6) { // TCP Protocol tracking
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

        // Check if the packet originates from our restricted target signature
        if (strcmp(src_ip, BANNED_IP) == 0) {
            printf("\n🚨 [FIREWALL ALERT] Traffic Intercepted from Restricted Host [%s]\n", BANNED_IP);
            printf("| Size: %d Bytes | Target Port: %d -> Local Port: %d\n", size, src_port, dest_port);
            
            // Check the connection initialization status
            if (tcph->syn && !tcph->ack) {
                printf("| Flags: [SYN] State: Unauthorized connection attempt detected!\n");
            } else if (tcph->rst) {
                printf("| Flags: [RST] State: Host dropped or scanned connection.\n");
            } else {
                printf("| Flags: [DATA STREAM] State: Processing active encrypted payload block.\n");
            }
            printf("------------------------------------------------------------------\n");
        }
    }
}

int main() {
    int sock_raw;
    struct sockaddr_in saddr;
    unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE); 

    printf("[+] Initializing Active IPS Security Firewall Engine...\n");
    printf("[*] Targeted Monitored Signature Host: %s\n", BANNED_IP);
    
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw < 0) {
        perror("Socket initialization failed. Execute utility with 'sudo'");
        free(buffer);
        return 1;
    }

    printf("[*] Firewall rule evaluation engine running. Analyzing stack packets...\n");

    while (1) {
        int saddr_size = sizeof(saddr);
        int data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&saddr, (socklen_t*)&saddr_size);
        if (data_size < 0) {
            perror("Packet processing pipeline fault");
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
