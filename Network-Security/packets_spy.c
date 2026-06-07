#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

#define BUFFER_SIZE 65536

void process_packet(unsigned char* buffer, int size) {
    struct iphdr *iph = (struct iphdr*)buffer;
    
    if (iph->protocol == 6) { // Filter for TCP streams
        struct sockaddr_in source, dest;
        memset(&source, 0, sizeof(source));
        memset(&dest, 0, sizeof(dest));
        
        source.sin_addr.s_addr = iph->saddr;
        dest.sin_addr.s_addr = iph->daddr;
        
        int ip_header_len = iph->ihl * 4;
        struct tcphdr *tcph = (struct tcphdr*)(buffer + ip_header_len);
        
        char src_ip[32], dest_ip[32];
        strcpy(src_ip, inet_ntoa(source.sin_addr));
        strcpy(dest_ip, inet_ntoa(dest.sin_addr));
        
        int src_port = ntohs(tcph->source);
        int dest_port = ntohs(tcph->dest);

        // Bitwise evaluation of TCP flag states
        int syn_set = tcph->syn;
        int ack_set = tcph->ack;
        int fin_set = tcph->fin;
        int rst_set = tcph->rst;

        // Categorize packet type based on flags
        if (syn_set && !ack_set) {
            printf("[!] CONNECTION REQUEST (SYN) ===> %s:%d -> %s:%d\n", src_ip, src_port, dest_ip, dest_port);
        } 
        else if (syn_set && ack_set) {
            printf("[✓] HANDSHAKE ACCEPTED (SYN-ACK) ===> %s:%d -> %s:%d\n", src_ip, src_port, dest_ip, dest_port);
        } 
        else if (rst_set) {
            printf("[X] CONNECTION RESET (RST) ===> %s:%d -> %s:%d [Potential Port Scan Artifact]\n", src_ip, src_port, dest_ip, dest_port);
        } 
        else if (fin_set) {
            printf("[-] DISCONNECTING (FIN) ===> %s:%d -> %s:%d\n", src_ip, src_port, dest_ip, dest_port);
        }
    }
}

int main() {
    int sock_raw;
    struct sockaddr_in saddr;
    unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE); 

    printf("[+] Initializing Raw Socket Protocol Flag Analyzer...\n");
    
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw < 0) {
        perror("Socket allocation failure. Execute binary with 'sudo'");
        free(buffer);
        return 1;
    }

    printf("[*] Real-time state machine inspection active...\n");

    while (1) {
        int saddr_size = sizeof(saddr);
        int data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&saddr, (socklen_t*)&saddr_size);
        if (data_size < 0) {
            perror("Packet stream extraction dropped");
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
