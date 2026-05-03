#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>

int main() {
    int sock;
    struct sockaddr_in server;
    char *target_ip = "127.0.0.1";
    struct timeval tv;
    fd_set fdset;

    printf("--- [Cyber-Toolbox] High-Speed Port Audit ---\n");

    for (int port = 1; port <= 1024; port++) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        // STEP 1: Set socket to Non-Blocking mode
        fcntl(sock, F_SETFL, O_NONBLOCK);

        server.sin_family = AF_INET;
        server.sin_addr.s_addr = inet_addr(target_ip);
        server.sin_port = htons(port);

        // STEP 2: Initiate connection
        // This returns immediately because of O_NONBLOCK
        connect(sock, (struct sockaddr *)&server, sizeof(server));

        // STEP 3: Use select() to wait with a custom timeout
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        
        tv.tv_sec = 0;
        tv.tv_usec = 500000; // 0.5 seconds (500ms)

        // select() checks if the socket is ready for writing (connection established)
        if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
            
            if (so_error == 0) {
                printf("[+] Port %d is OPEN\n", port);
            }
        }

        close(sock);
    }

    printf("Audit Complete.\n");
    return 0;
}
