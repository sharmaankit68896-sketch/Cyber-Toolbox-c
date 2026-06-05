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
    // 1. Isolate the IP Header Layer
    struct iphdr *iph = (struct iphdr*)buffer;
    
    // Filter strictly for TCP protocol streams (Protocol Code 6)
    if (iph->protocol == 6) {
        struct sockaddr_in source, dest;
        memset(&source, 0, sizeof(source));
        memset(&dest, 0, sizeof(dest));
        
        source.sin_addr.s_addr = iph->saddr;
        dest.sin_addr.s_addr = iph->daddr;
        
        // 2. Calculate the exact size of the IP Header using the 'ihl' (Internet Header Length) field
        // The ihl represents the number of 32-bit words, so multiply by 4 to get total bytes.
        int ip_header_len = iph->ihl * 4;
        
        // 3. Jump memory address directly past the IP Header to locate the start of the TCP Header
        struct tcphdr *tcph = (struct tcphdr*)(buffer + ip_header_len);
        
        printf("[TCP STREAM] %s : %d ===> ", inet_ntoa(source.sin_addr), ntohs(tcph->source));
        printf("%s : %d | Size: %d Bytes | Window: %d\n", 
               inet_ntoa(dest.sin_addr), ntohs(tcph->dest), ntohs(iph->tot_len), ntohs(tcph->window));
    }
}

int main() {
    int sock_raw;
    struct sockaddr_in saddr;
    unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE); 

    printf("[+] Initializing Advanced Layer 4 TCP/IP Decoder...\n");
    
    // Open raw socket intercepting network IP protocol layers
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw < 0) {
        perror("Socket allocation failed. Verification requirement: Run execution via 'sudo'");
        free(buffer);
        return 1;
    }

    printf("[*] Forensic network layer interception active...\n");

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
