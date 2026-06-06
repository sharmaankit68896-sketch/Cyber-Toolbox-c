#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>

#define BUFFER_SIZE 65536

void PrintData(unsigned char* data, int Size) {
    int i;
    int has_printable = 0;

    // First pass: Quick check to see if there's any readable text inside
    for (i = 0; i < Size; i++) {
        if (isprint(data[i])) {
            has_printable = 1;
            break;
        }
    }

    if (!has_printable) {
        printf(" [Binary Data Payload]\n");
        return;
    }

    printf("\n--- [ PAYLOAD START ] ---\n");
    for (i = 0; i < Size; i++) {
        if (isprint(data[i])) {
            printf("%c", data[i]);
        } else if (data[i] == '\n' || data[i] == '\r') {
            printf("%c", data[i]); 
        } else {
            printf(".");
        }
    }
    printf("\n--- [ PAYLOAD END ] ---\n\n");
}

void process_packet(unsigned char* buffer, int size) {
    struct iphdr *iph = (struct iphdr*)buffer;
    
    if (iph->protocol == 6) { // TCP Protocol
        struct sockaddr_in source, dest;
        memset(&source, 0, sizeof(source));
        memset(&dest, 0, sizeof(dest));
        
        source.sin_addr.s_addr = iph->saddr;
        dest.sin_addr.s_addr = iph->daddr;
        
        int ip_header_len = iph->ihl * 4;
        struct tcphdr *tcph = (struct tcphdr*)(buffer + ip_header_len);
        int tcp_header_len = tcph->doff * 4;
        
        int header_size = ip_header_len + tcp_header_len;
        unsigned char *payload = buffer + header_size;
        int payload_size = size - header_size;
        
        if (payload_size > 0) {
            printf("[TCP STREAM] %s:%d ===> ", inet_ntoa(source.sin_addr), ntohs(tcph->source));
            printf("%s:%d | Payload: %d Bytes", inet_ntoa(dest.sin_addr), ntohs(tcph->dest), payload_size);
            PrintData(payload, payload_size);
        }
    }
}

int main() {
    int sock_raw;
    struct sockaddr_in saddr;
    unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE); 

    printf("[+] Initializing Layer 7 Forensic Payload Extractor...\n");
    
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw < 0) {
        perror("Socket allocation failed. Run via 'sudo'");
        free(buffer);
        return 1;
    }

    printf("[*] Listening for unencrypted application payloads...\n");

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
