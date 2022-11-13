#include <cstdio>
#include <cstdint>

// byT3c0d3_1nT3rpr3T3r_1s_4_L0T_0f_fun

uint32_t hash(uint32_t x) {
    uint32_t ret = 0xacab3c0u;
    for (int i = 0; i < 4; i++) {
        uint32_t v9 = (x >> (i * 8)) & 0xff;
        ret = ((ret ^ v9) << 8) | (ret >> 24);
    }
    return ret;
}

int main() {
    uint32_t flagParts[] = {
            0x739e80a2,
            0x3aae80a3,
            0x3ba4e79f,
            0x78bac1f3,
            0x5ef9c1f3,
            0x3bb9ec9f,
            0x558683f4,
            0x55fad594,
            0x6cbfdd9f,
    };
    uint32_t decFlag[10] {};

    for (int j = 0; j < 9; j++) {
        auto find = flagParts[j];
        for (uint64_t i = 0; i < 0x100000000LLu; i++) {
            if (hash(i) == find) {
                printf("%x\n", (uint32_t) i);
                decFlag[j] = (uint32_t) i;
                printf("%s\n", (const char*) decFlag);
            }
        }
    }
    return 0;
}
