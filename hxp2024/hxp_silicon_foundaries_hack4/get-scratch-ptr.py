import pwndbg
from pwndbg.search import search
from pwndbg.aglib import memory
from pwn import p64

"""
We look for this duplicated string:
    mr->name = g_strdup(name) = g_strdup("ai1337-scratch")

This duplication is done in:
    memory_region_init_ram_ptr
        memory_region_init
            ...

The structure it is written to is MemoryRegion which looks like this:
    struct MemoryRegion {
        Object parent_obj;
        // private:
        // The following fields should fit in a cache line
        bool romd_mode;
        bool ram;
        bool subpage;
        bool readonly; // For RAM regions
        bool nonvolatile;
        bool rom_device;
        bool flush_coalesced_mmio;
        bool unmergeable;
        uint8_t dirty_log_mask;
        bool is_iommu;
        RAMBlock *ram_block;
        // ... - lots of fields here
        const char* name;
"""
ai_str_addr = next(pwndbg.search.search(b'ai1337-scratch', writable=1))

print("ai1337-scratch @ %#x" % ai_str_addr)

"""
We eventually look for stack pointer stored in:
    struct RAMBlock {
        struct rcu_head rcu;
        struct MemoryRegion *mr;
        uint8_t *host;

By code:
    mr->ram_block = qemu_ram_alloc_from_ptr(size, ptr, mr, &error_abort);
"""

ai_str_addr_at = next(search(p64(ai_str_addr)))
print("ptr to ai1337-scratch @ %#x" % ai_str_addr_at)

ram_block_addr_at = ai_str_addr_at-0xb0
print("&mr_ram_block @ %#x" % ram_block_addr_at)

ram_block_addr = memory.u64(ram_block_addr_at)
print("RamBlock @ %#x" % ram_block_addr)

ram_block_host_ptr_at = ram_block_addr + 0x18
print("&RamBlock->host @ %#x" % ram_block_host_ptr_at)

host_ptr = memory.u64(ram_block_host_ptr_at)
print("scratch[...] @ %#x"  % host_ptr)

