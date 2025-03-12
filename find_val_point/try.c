#include <stdio.h>
#include <stdlib.h>

int main(){
    setpgid(0, 0); 
    printf("My PID: %d, PGID: %d\n", getpid(), getpgid(0));
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "sudo insmod kprobe.ko target_pgid=%d", getpgid(0));
    system(cmd);
    int fd=open("kprobe.c",0);
    close(fd);
	}
