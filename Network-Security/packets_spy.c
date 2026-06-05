#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>

#define BUFFER_SIZE 65536

void process_packet(unsigned char* buffer, int size) {
    // The IP header sits at the very beginning of the raw network buffer
    struct iphdr *iph = (struct iphdr*)buffer;
    
    struct sockaddr_in source, dest;
    memset(&source, 0, sizeof(source));
    memset(&dest, 0, sizeof(dest));
    
    source.sin_addr.s_addr = iph->saddr;
    dest.sin_addr.s_addr = iph->daddr;
    
    printf("[PACKET] Protocol: %d | Code: %s ===> ", (int)iph->protocol, inet_ntoa(source.sin_addr));
    printf("%s | Total Size: %d Bytes\n", inet_ntoa(dest.sin_addr), ntohs(iph->tot_len));
}

int main() {
    int sock_raw;
    struct sockaddr_in saddr;
    unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE); 

    printf("[+] Initializing Raw Network Socket Interceptor...\n");
    
    // ETH_P_ALL captures all protocols. Requires ROOT privileges to execute.
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw < 0) {
        perror("Socket initialization failed. Are you root?");
        free(buffer);
        return 1;
    }

    printf("[*] Sniffer active. Intercepting live TCP/IP streams...\n");

    while (1) {
        int saddr_size = sizeof(saddr);
        // Pull raw bytes directly out of the network interface card
        int data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&saddr, (socklen_t*)&saddr_size);
        if (data_size < 0) {
            perror("Failed to fetch packet stream");
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
