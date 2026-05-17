#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>

int main() {
    struct dirent *de; 
    DIR *dr = opendir("."); // Open current directory

    if (dr == NULL) {
        printf("Could not open current directory" );
        return 0;
    }

    while ((de = readdir(dr)) != NULL) {
        printf("Found artifact: %s\n", de->d_name);
    }

    closedir(dr);    
    return 0;
}
