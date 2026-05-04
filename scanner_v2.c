#include <pthread.h>

// Structure to pass data to the thread
struct port_range {
    int start;
    int end;
    char *ip;
};

void* scan_range(void* arg) {
    struct port_range *range = (struct port_range*)arg;
    for (int i = range->start; i <= range->end; i++) {
        // ... [Your existing socket connection logic here] ...
    }
    return NULL;
}

// In main:
pthread_t thread1, thread2;
struct port_range r1 = {1, 500, "127.0.0.1"};
struct port_range r2 = {501, 1000, "127.0.0.1"};

pthread_create(&thread1, NULL, scan_range, &r1);
pthread_create(&thread2, NULL, scan_range, &r2);

pthread_join(thread1, NULL); // Wait for thread 1 to finish
pthread_join(thread2, NULL); // Wait for thread 2 to finish

