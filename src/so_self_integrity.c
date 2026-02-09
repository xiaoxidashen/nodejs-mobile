/**
 * SO 自身完整性校验：
 * 1) 运行时定位当前 SO 文件；
 * 2) 只对 ELF 的 .text 段计算 SHA-256；
 * 3) 与数据段中预留的 hash 槽位比对，不一致则延时退出。
 *
 * 说明：
 * - 该文件是独立方案，不依赖 JNI。
 * - 编译后需运行 tools/patch_so_text_hash.py 回填真实 hash。
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <pthread.h>
#include <android/log.h>

#define AG_SI_TAG "ag-so-self"
#ifndef AG_NO_LOG
#define AG_NO_LOG 1
#endif
#if defined(AG_NO_LOG) || defined(NDEBUG)
  #define AG_SI_LOG(...) ((void)0)
#else
  #define AG_SI_LOG(...) __android_log_print(ANDROID_LOG_DEBUG, AG_SI_TAG, __VA_ARGS__)
#endif

#define AG_SI_HASH_SIZE 32U
#define AG_SI_MAGIC_SIZE 8U

typedef struct {
    uint8_t magic[AG_SI_MAGIC_SIZE];
    uint8_t hash[AG_SI_HASH_SIZE];
} ag_si_hash_slot;

typedef struct {
    uint64_t offset;
    uint64_t size;
} ag_si_text_range;

/* 定义在不同编译器下都可用的“保留符号”标记，避免链接阶段被裁剪。 */
#if defined(__clang__)
#define AG_SI_RETAIN __attribute__((used, retain))
#else
#define AG_SI_RETAIN __attribute__((used))
#endif

/* 回填脚本按该魔数定位 hash 槽位；使用 volatile 防止常量折叠。 */
AG_SI_RETAIN
__attribute__((section(".data.ag_si")))
static volatile ag_si_hash_slot AG_SI_HASH_SLOT = {
    {0xa6, 0x5d, 0xc2, 0x19, 0x7e, 0x34, 0xeb, 0x90},
    {0x82, 0xc1, 0x04, 0x7b, 0xbe, 0xfd, 0x30, 0x77,
     0xaa, 0xe9, 0x2c, 0x63, 0xa6, 0xe5, 0xd8, 0x1f,
     0x52, 0x91, 0xd4, 0x0b, 0x4e, 0x8d, 0xc0, 0x07,
     0x7a, 0xb9, 0xfc, 0x33, 0x76, 0xb5, 0xe8, 0x2f}
};

typedef struct {
    uint32_t h[8];
    uint8_t buf[64];
    uint64_t total;
} ag_si_sha256_ctx;

static const uint32_t AG_SI_SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* 提前声明 constructor，供 maps 定位函数用自身地址反查 so 路径。 */
static void ag_so_self_integrity_init(void);

/* 右旋 32 位整数。 */
static uint32_t ag_si_rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

/* 执行 SHA-256 单块压缩。 */
static void ag_si_sha256_compress(ag_si_sha256_ctx *ctx, const uint8_t block[64]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ag_si_rotr(w[i - 15], 7) ^ ag_si_rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ag_si_rotr(w[i - 2], 17) ^ ag_si_rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];
    f = ctx->h[5];
    g = ctx->h[6];
    h = ctx->h[7];

    for (i = 0; i < 64; i++) {
        uint32_t S1 = ag_si_rotr(e, 6) ^ ag_si_rotr(e, 11) ^ ag_si_rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + AG_SI_SHA256_K[i] + w[i];
        uint32_t S0 = ag_si_rotr(a, 2) ^ ag_si_rotr(a, 13) ^ ag_si_rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
    ctx->h[5] += f;
    ctx->h[6] += g;
    ctx->h[7] += h;
}

/* 初始化 SHA-256 上下文。 */
static void ag_si_sha256_init(ag_si_sha256_ctx *ctx) {
    ctx->h[0] = 0x6a09e667;
    ctx->h[1] = 0xbb67ae85;
    ctx->h[2] = 0x3c6ef372;
    ctx->h[3] = 0xa54ff53a;
    ctx->h[4] = 0x510e527f;
    ctx->h[5] = 0x9b05688c;
    ctx->h[6] = 0x1f83d9ab;
    ctx->h[7] = 0x5be0cd19;
    ctx->total = 0;
}

/* 增量写入 SHA-256 输入数据。 */
static void ag_si_sha256_update(ag_si_sha256_ctx *ctx, const uint8_t *data, size_t len) {
    size_t used = (size_t)(ctx->total % 64);
    ctx->total += len;

    if (used != 0) {
        size_t space = 64 - used;
        size_t copy_len = len < space ? len : space;
        memcpy(ctx->buf + used, data, copy_len);
        data += copy_len;
        len -= copy_len;
        used += copy_len;
        if (used == 64) {
            ag_si_sha256_compress(ctx, ctx->buf);
        }
    }

    while (len >= 64) {
        ag_si_sha256_compress(ctx, data);
        data += 64;
        len -= 64;
    }

    if (len > 0) {
        memcpy(ctx->buf, data, len);
    }
}

/* 结束 SHA-256 计算并输出 32 字节摘要。 */
static void ag_si_sha256_final(ag_si_sha256_ctx *ctx, uint8_t out[AG_SI_HASH_SIZE]) {
    uint64_t bits = ctx->total * 8;
    size_t used = (size_t)(ctx->total % 64);
    int i;

    ctx->buf[used++] = 0x80;
    if (used > 56) {
        memset(ctx->buf + used, 0, 64 - used);
        ag_si_sha256_compress(ctx, ctx->buf);
        used = 0;
    }
    memset(ctx->buf + used, 0, 56 - used);

    for (i = 0; i < 8; i++) {
        ctx->buf[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
    }
    ag_si_sha256_compress(ctx, ctx->buf);

    for (i = 0; i < 8; i++) {
        out[i * 4] = (uint8_t)(ctx->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(ctx->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(ctx->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(ctx->h[i]);
    }
}

/* 从文件指定偏移完整读取指定字节数。 */
static int ag_si_read_at(int fd, off_t offset, void *buf, size_t len) {
    size_t done = 0;
    if (lseek(fd, offset, SEEK_SET) != offset) return 0;
    while (done < len) {
        ssize_t n = read(fd, (uint8_t *)buf + done, len - done);
        if (n <= 0) return 0;
        done += (size_t)n;
    }
    return 1;
}

/* 判断 [offset, offset+size] 是否在文件范围内。 */
static int ag_si_range_valid(uint64_t offset, uint64_t size, uint64_t file_size) {
    if (offset > file_size) return 0;
    if (size > file_size - offset) return 0;
    return 1;
}

/* 从 /proc/self/maps 中按当前函数地址反查所属 so 路径。 */
static int ag_si_find_self_so_path(char *out, size_t out_size) {
    FILE *fp;
    char line[1024];
    uintptr_t self_addr = (uintptr_t)(void *)&ag_so_self_integrity_init;

    fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    while (fgets(line, sizeof(line), fp)) {
        unsigned long start = 0;
        unsigned long end = 0;
        char perms[5] = {0};
        char path[512] = {0};
        int matched = sscanf(line, "%lx-%lx %4s %*s %*s %*s %511[^\n]", &start, &end, perms, path);
        if (matched < 3) continue;
        if (self_addr < (uintptr_t)start || self_addr >= (uintptr_t)end) continue;
        if (matched < 4) continue;
        if (path[0] != '/') continue;

        {
            size_t len = strlen(path);
            const char deleted_suffix[] = " (deleted)";
            size_t suffix_len = sizeof(deleted_suffix) - 1;
            if (len >= suffix_len && strcmp(path + len - suffix_len, deleted_suffix) == 0) {
                path[len - suffix_len] = '\0';
                len -= suffix_len;
            }
            if (len + 1 > out_size) continue;
            memcpy(out, path, len + 1);
            fclose(fp);
            return 1;
        }
    }

    fclose(fp);
    return 0;
}

/* 解析 ELF64，提取 .text 段文件偏移和长度。 */
static int ag_si_find_text_elf64(int fd, uint64_t file_size, ag_si_text_range *out) {
    Elf64_Ehdr eh;
    Elf64_Shdr shstr_hdr;
    char *shstr = NULL;
    uint16_t i;

    if (!ag_si_read_at(fd, 0, &eh, sizeof(eh))) return 0;
    if (eh.e_shoff == 0 || eh.e_shentsize < sizeof(Elf64_Shdr) || eh.e_shnum == 0) return 0;
    if (eh.e_shstrndx >= eh.e_shnum) return 0;
    if (!ag_si_range_valid((uint64_t)eh.e_shoff, (uint64_t)eh.e_shentsize * eh.e_shnum, file_size)) return 0;

    if (!ag_si_read_at(fd,
                       (off_t)(eh.e_shoff + (uint64_t)eh.e_shentsize * eh.e_shstrndx),
                       &shstr_hdr,
                       sizeof(shstr_hdr))) return 0;
    if (!ag_si_range_valid(shstr_hdr.sh_offset, shstr_hdr.sh_size, file_size)) return 0;
    if (shstr_hdr.sh_size == 0 || shstr_hdr.sh_size > 4 * 1024 * 1024ULL) return 0;

    shstr = (char *)malloc((size_t)shstr_hdr.sh_size);
    if (!shstr) return 0;
    if (!ag_si_read_at(fd, (off_t)shstr_hdr.sh_offset, shstr, (size_t)shstr_hdr.sh_size)) {
        free(shstr);
        return 0;
    }

    for (i = 0; i < eh.e_shnum; i++) {
        Elf64_Shdr sh;
        if (!ag_si_read_at(fd,
                           (off_t)(eh.e_shoff + (uint64_t)eh.e_shentsize * i),
                           &sh,
                           sizeof(sh))) {
            free(shstr);
            return 0;
        }

        if (sh.sh_name < shstr_hdr.sh_size) {
            const char *name = shstr + sh.sh_name;
            size_t remain = (size_t)(shstr_hdr.sh_size - sh.sh_name);
            if (memchr(name, '\0', remain) != NULL && strcmp(name, ".text") == 0) {
                if (!ag_si_range_valid(sh.sh_offset, sh.sh_size, file_size)) {
                    free(shstr);
                    return 0;
                }
                out->offset = sh.sh_offset;
                out->size = sh.sh_size;
                free(shstr);
                return 1;
            }
        }
    }

    free(shstr);
    return 0;
}

/* 解析 ELF32，提取 .text 段文件偏移和长度。 */
static int ag_si_find_text_elf32(int fd, uint64_t file_size, ag_si_text_range *out) {
    Elf32_Ehdr eh;
    Elf32_Shdr shstr_hdr;
    char *shstr = NULL;
    uint16_t i;

    if (!ag_si_read_at(fd, 0, &eh, sizeof(eh))) return 0;
    if (eh.e_shoff == 0 || eh.e_shentsize < sizeof(Elf32_Shdr) || eh.e_shnum == 0) return 0;
    if (eh.e_shstrndx >= eh.e_shnum) return 0;
    if (!ag_si_range_valid((uint64_t)eh.e_shoff, (uint64_t)eh.e_shentsize * eh.e_shnum, file_size)) return 0;

    if (!ag_si_read_at(fd,
                       (off_t)((uint64_t)eh.e_shoff + (uint64_t)eh.e_shentsize * eh.e_shstrndx),
                       &shstr_hdr,
                       sizeof(shstr_hdr))) return 0;
    if (!ag_si_range_valid(shstr_hdr.sh_offset, shstr_hdr.sh_size, file_size)) return 0;
    if (shstr_hdr.sh_size == 0 || shstr_hdr.sh_size > 4 * 1024 * 1024ULL) return 0;

    shstr = (char *)malloc((size_t)shstr_hdr.sh_size);
    if (!shstr) return 0;
    if (!ag_si_read_at(fd, (off_t)shstr_hdr.sh_offset, shstr, (size_t)shstr_hdr.sh_size)) {
        free(shstr);
        return 0;
    }

    for (i = 0; i < eh.e_shnum; i++) {
        Elf32_Shdr sh;
        if (!ag_si_read_at(fd,
                           (off_t)((uint64_t)eh.e_shoff + (uint64_t)eh.e_shentsize * i),
                           &sh,
                           sizeof(sh))) {
            free(shstr);
            return 0;
        }

        if (sh.sh_name < shstr_hdr.sh_size) {
            const char *name = shstr + sh.sh_name;
            size_t remain = (size_t)(shstr_hdr.sh_size - sh.sh_name);
            if (memchr(name, '\0', remain) != NULL && strcmp(name, ".text") == 0) {
                if (!ag_si_range_valid(sh.sh_offset, sh.sh_size, file_size)) {
                    free(shstr);
                    return 0;
                }
                out->offset = sh.sh_offset;
                out->size = sh.sh_size;
                free(shstr);
                return 1;
            }
        }
    }

    free(shstr);
    return 0;
}

/* 识别 ELF 位宽并提取 .text 段文件范围。 */
static int ag_si_find_text_section(int fd, uint64_t file_size, ag_si_text_range *out) {
    uint8_t ident[EI_NIDENT];
    if (!ag_si_read_at(fd, 0, ident, sizeof(ident))) return 0;
    if (!(ident[0] == 0x7f && ident[1] == 'E' && ident[2] == 'L' && ident[3] == 'F')) return 0;
    if (ident[EI_DATA] != ELFDATA2LSB) return 0;

    if (ident[EI_CLASS] == ELFCLASS64) {
        return ag_si_find_text_elf64(fd, file_size, out);
    }
    if (ident[EI_CLASS] == ELFCLASS32) {
        return ag_si_find_text_elf32(fd, file_size, out);
    }
    return 0;
}

/* 读取 so 文件并计算其 .text 段 SHA-256。 */
static int ag_si_hash_text_from_file(const char *so_path, uint8_t out_hash[AG_SI_HASH_SIZE]) {
    int fd;
    off_t file_size_off;
    uint64_t file_size;
    ag_si_text_range text;
    ag_si_sha256_ctx ctx;
    uint8_t buf[4096];
    uint64_t remain;

    fd = open(so_path, O_RDONLY);
    if (fd < 0) return 0;

    file_size_off = lseek(fd, 0, SEEK_END);
    if (file_size_off <= 0) {
        close(fd);
        return 0;
    }
    file_size = (uint64_t)file_size_off;

    if (!ag_si_find_text_section(fd, file_size, &text)) {
        close(fd);
        return 0;
    }
    if (text.size == 0) {
        close(fd);
        return 0;
    }
    if (lseek(fd, (off_t)text.offset, SEEK_SET) != (off_t)text.offset) {
        close(fd);
        return 0;
    }

    ag_si_sha256_init(&ctx);
    remain = text.size;
    while (remain > 0) {
        size_t want = remain > sizeof(buf) ? sizeof(buf) : (size_t)remain;
        ssize_t n = read(fd, buf, want);
        if (n <= 0) {
            close(fd);
            return 0;
        }
        ag_si_sha256_update(&ctx, buf, (size_t)n);
        remain -= (uint64_t)n;
    }
    ag_si_sha256_final(&ctx, out_hash);
    close(fd);
    return 1;
}

/* 常量时间比较，避免早停泄露前缀信息。 */
static int ag_si_consttime_eq(const uint8_t *a, const volatile uint8_t *b, size_t len) {
    volatile uint8_t diff = 0;
    size_t i;
    for (i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

/* 后台线程：休眠指定秒数后静默终止进程。 */
static void *ag_si_delayed_exit_thread(void *arg) {
    unsigned int secs = *(unsigned int *)arg;
    free(arg);
    sleep(secs);
    _exit(0);
    return NULL;
}

/* 启动延迟退出：从 /dev/urandom 取随机值，60-600 秒后终止。 */
static void ag_si_schedule_exit(void) {
    pthread_t tid;
    unsigned int *secs;
    uint32_t rnd = 0;
    int ufd = open("/dev/urandom", O_RDONLY);
    if (ufd >= 0) {
        read(ufd, &rnd, sizeof(rnd));
        close(ufd);
    }
    secs = (unsigned int *)malloc(sizeof(unsigned int));
    if (!secs) {
        _exit(0);
        return;
    }
    *secs = 60 + (rnd % 541);
    pthread_create(&tid, NULL, ag_si_delayed_exit_thread, secs);
    pthread_detach(tid);
}

/* SO 加载后执行 .text 完整性校验，不通过则触发延时终止。 */
__attribute__((constructor))
static void ag_so_self_integrity_init(void) {
    char so_path[512];
    uint8_t digest[AG_SI_HASH_SIZE];

    if (!ag_si_find_self_so_path(so_path, sizeof(so_path))) {
        AG_SI_LOG("self-integrity failed: cannot locate so path");
        ag_si_schedule_exit();
        return;
    }

    if (!ag_si_hash_text_from_file(so_path, digest)) {
        AG_SI_LOG("self-integrity failed: cannot hash .text");
        ag_si_schedule_exit();
        return;
    }

    if (!ag_si_consttime_eq(digest, AG_SI_HASH_SLOT.hash, AG_SI_HASH_SIZE)) {
        AG_SI_LOG("self-integrity failed: .text hash mismatch");
        ag_si_schedule_exit();
        return;
    }

    AG_SI_LOG("self-integrity pass");
}
