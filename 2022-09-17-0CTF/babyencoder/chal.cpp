#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <unistd.h>
#include <fcntl.h>

static int randfd;

void urand_init() {
    randfd = open("/dev/urandom", 0);
    if (randfd == -1) {
        puts("error");
        exit(-1);
    }
}

int urand() {
    if (randfd == -1)
        urand_init();
    int ret;
    read(randfd, &ret, 4uLL);
    return ret;
}

static constexpr double C_PI = 3.141592653589793;

void do_block(double *ret, char v1, char v2, char v3, char v4, char v5, char v6, char v7, char v8) {
    int o1 = (int) (C_PI / 64.0 * (double) (urand() % 255));
    int o2 = (int) (C_PI / 64.0 * (double) (urand() % 255));
    int o3 = (int) (C_PI / 64.0 * (double) (urand() % 255));
    int o4 = (int) (C_PI / 64.0 * (double) (urand() % 255));
    int o5 = (int) (C_PI / 64.0 * (double) (urand() % 255));
    int o6 = (int) (C_PI / 64.0 * (double) (urand() % 255));
    int o7 = (int) (C_PI / 64.0 * (double) (urand() % 255));
    int o8 = (int) (C_PI / 64.0 * (double) (urand() % 255));
    int v30 = urand() % 255;
    for (int i = 0; i <= 127; ++i) {
        double c = 0.0;
        c =  cos((C_PI + C_PI) * 1.0 * (i / 128.0) + o1) * (double) v1;
        c += cos((C_PI + C_PI) * 2.0 * (i / 128.0) + o2) * (double) v2;
        c += cos((C_PI + C_PI) * 3.0 * (i / 128.0) + o3) * (double) v3;
        c += cos((C_PI + C_PI) * 4.0 * (i / 128.0) + o4) * (double) v4;
        c += cos((C_PI + C_PI) * 5.0 * (i / 128.0) + o5) * (double) v5;
        c += cos((C_PI + C_PI) * 6.0 * (i / 128.0) + o6) * (double) v6;
        c += cos((C_PI + C_PI) * 7.0 * (i / 128.0) + o7) * (double) v7;
        c += cos((C_PI + C_PI) * 8.0 * (i / 128.0) + o8) * (double) v8;
        c += (double) v30 + (double) (urand() % 3);
        ret[i] = c;
    }
}

int main(int a1, char **a2, char **a3) {
    uint8_t v6[8192];
    uint8_t buf[0x64];
    char s1[112];
    uint8_t v10[0x64];

    setbuf(stdin, nullptr);
    setbuf(stdout, nullptr);
    setbuf(stderr, nullptr);
    alarm(0x1Eu);
    urand_init();
    memset(buf, 0, sizeof(buf));
    read(randfd, buf, 0x40uLL);
    for (int i = 0; i <= 63; ++i)
        buf[i] = buf[i] % 0x5Fu + 32;
    memset(v6, 0, sizeof(v6));
    for (int j = 0; j <= 7; ++j) {
        do_block(
                (double *) &v6[128 * 8 * j],
                buf[8 * j],
                buf[8 * j + 1],
                buf[8 * j + 2],
                buf[8 * j + 3],
                buf[8 * j + 4],
                buf[8 * j + 5],
                buf[8 * j + 6],
                buf[8 * j + 7]);
    }
    puts("========START=======");
    write(1, v6, 0x2000uLL);
    puts("=========END========");
    close(randfd);
    read(0, s1, 0x40uLL);
    if (!memcmp(s1, buf, 0x40uLL)) {
        int fd = open("/flag", 0);
        memset(v10, 0, sizeof(v10));
        read(fd, v10, 0x40uLL);
        printf("Success!Here is your flag:%s", (const char *) v10);
        close(fd);
        exit(0);
    }
    puts("GG");
    return 0;
}