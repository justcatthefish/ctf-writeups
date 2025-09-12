#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/prctl.h>

typedef struct scratch_info {
    uint64_t scratch_addr;
    uint64_t scratch_default_size;
    uint32_t scratch_max_slice_size;
    uint16_t scratch_max_slice_count;
} scratch_info;

void get_scratch_info(scratch_info *info);
void load_scratch(uint64_t slice, uint64_t slice_offset, void *source, uint64_t length);
void read_scratch(uint64_t slice, uint64_t slice_offset, void *destination, uint64_t length);
void clear_scratch();
void add_slices(uint64_t slice_a, uint64_t slice_b, uint64_t slice_c);
void sub_slices(uint64_t slice_a, uint64_t slice_b, uint64_t slice_c);
void mul_slices(uint64_t slice_a, uint64_t slice_b, uint64_t slice_c);

int main() {
    // Gather info about scratch memory
    scratch_info info = {0};
    get_scratch_info(&info);
    printf("Scratch info:\n");
    printf(" - scratch addr: 0x%lx\n", info.scratch_addr);
    printf(" - scratch default size: 0x%lx bytes\n", info.scratch_default_size);
    printf(" - scratch max slice size: 0x%x bytes\n", info.scratch_max_slice_size);
    printf(" - scratch max slice count: %u\n", info.scratch_max_slice_count);

    size_t slice_size_value = 1024;

    // Allocate buffers A, B, D and load into scratch memory at slices 0, 1, 3
    void *a = malloc(1024);
    memset(a, 0x20, 1024);
    load_scratch(0, 0, a, slice_size_value);

    void *b = malloc(1024);
    memset(b, 0x40, 1024);
    load_scratch(1, 0, b, slice_size_value);

    uint64_t *d = malloc(1024);
    for (size_t i = 0; i < 1024 / 8; ++i) {
        d[i] = 2;
    }
    load_scratch(3, 0, d, slice_size_value);

    // Add slices 0 and 1, write results into slice 2
    add_slices(0, 1, 2);

    // Multiply slices 2 and 3, write resutls into slice 3
    mul_slices(2, 3, 3);

    // Read back result from slice into array D
    read_scratch(3, 0, d, slice_size_value);

    // Print a couple of values
    for (size_t i = 0; i < 8; ++i) {
        printf("slice_3[%zu] = 0x%lx\n", i, d[i]);
    }

    // Quick clear scratch memory
    clear_scratch();

    return 0;
}
