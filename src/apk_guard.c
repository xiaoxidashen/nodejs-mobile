/**
 * APK 签名校验 - 纯 C 自包含实现，可直接丢入任何 Android SO 构建系统。
 * constructor 自动触发，通过 /proc/self/maps 获取 APK 路径，零 JNI 依赖。
 * 优先使用 V2 签名，回退到 V1 (META-INF/ 下的 .RSA PKCS#7)。
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <android/log.h>

#define AG_TAG "ag-verify"
#ifndef AG_NO_LOG
#define AG_NO_LOG 1
#endif
/* 定义 AG_NO_LOG=1 或依赖构建系统的 NDEBUG 来关闭日志 */
#if defined(AG_NO_LOG) || defined(NDEBUG)
  #define AG_LOG(...) ((void)0)
#else
  #define AG_LOG(...) __android_log_print(ANDROID_LOG_DEBUG, AG_TAG, __VA_ARGS__)
#endif

/* ════════════════════════════════════════════════════════════════════════
   SHA-256 (FIPS 180-4)
   ════════════════════════════════════════════════════════════════════════ */

static const uint32_t AG_K[64] = {
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
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

typedef struct {
    uint32_t h[8];
    uint8_t  buf[64];
    uint64_t total;
} ag_sha256_ctx;

/* 右旋转 */
static uint32_t ag_rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

/* SHA-256 单块压缩 */
static void ag_sha256_compress(ag_sha256_ctx *ctx, const uint8_t block[64]) {
    uint32_t w[64];
    int i;
    uint32_t a, b, c, d, e, f, g, hh;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i*4] << 24) |
               ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) |
               ((uint32_t)block[i*4+3]);
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ag_rotr(w[i-15], 7) ^ ag_rotr(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ag_rotr(w[i-2], 17) ^ ag_rotr(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    a = ctx->h[0]; b = ctx->h[1]; c = ctx->h[2]; d = ctx->h[3];
    e = ctx->h[4]; f = ctx->h[5]; g = ctx->h[6]; hh = ctx->h[7];

    for (i = 0; i < 64; i++) {
        uint32_t S1 = ag_rotr(e, 6) ^ ag_rotr(e, 11) ^ ag_rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = hh + S1 + ch + AG_K[i] + w[i];
        uint32_t S0 = ag_rotr(a, 2) ^ ag_rotr(a, 13) ^ ag_rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d;
    ctx->h[4] += e; ctx->h[5] += f; ctx->h[6] += g; ctx->h[7] += hh;
}

/* 初始化 SHA-256 上下文 */
static void ag_sha256_init(ag_sha256_ctx *ctx) {
    ctx->h[0] = 0x6a09e667; ctx->h[1] = 0xbb67ae85;
    ctx->h[2] = 0x3c6ef372; ctx->h[3] = 0xa54ff53a;
    ctx->h[4] = 0x510e527f; ctx->h[5] = 0x9b05688c;
    ctx->h[6] = 0x1f83d9ab; ctx->h[7] = 0x5be0cd19;
    ctx->total = 0;
}

/* 增量更新 SHA-256 哈希 */
static void ag_sha256_update(ag_sha256_ctx *ctx, const uint8_t *data, size_t len) {
    size_t buf_used = ctx->total % 64;
    ctx->total += len;

    if (buf_used > 0) {
        size_t space = 64 - buf_used;
        size_t copy = len < space ? len : space;
        memcpy(ctx->buf + buf_used, data, copy);
        data += copy;
        len -= copy;
        buf_used += copy;
        if (buf_used == 64) {
            ag_sha256_compress(ctx, ctx->buf);
        }
    }
    while (len >= 64) {
        ag_sha256_compress(ctx, data);
        data += 64;
        len -= 64;
    }
    if (len > 0) {
        memcpy(ctx->buf, data, len);
    }
}

/* 完成哈希计算并输出 32 字节摘要 */
static void ag_sha256_final(ag_sha256_ctx *ctx, uint8_t digest[32]) {
    uint64_t total_bits = ctx->total * 8;
    size_t buf_used = ctx->total % 64;
    int i;

    ctx->buf[buf_used++] = 0x80;
    if (buf_used > 56) {
        memset(ctx->buf + buf_used, 0, 64 - buf_used);
        ag_sha256_compress(ctx, ctx->buf);
        buf_used = 0;
    }
    memset(ctx->buf + buf_used, 0, 56 - buf_used);

    for (i = 0; i < 8; i++) {
        ctx->buf[56 + i] = (uint8_t)(total_bits >> (56 - i * 8));
    }
    ag_sha256_compress(ctx, ctx->buf);

    for (i = 0; i < 8; i++) {
        digest[i*4]   = (uint8_t)(ctx->h[i] >> 24);
        digest[i*4+1] = (uint8_t)(ctx->h[i] >> 16);
        digest[i*4+2] = (uint8_t)(ctx->h[i] >> 8);
        digest[i*4+3] = (uint8_t)(ctx->h[i]);
    }
}

/* 一次性计算 SHA-256 */
static void ag_sha256(const uint8_t *data, size_t len, uint8_t digest[32]) {
    ag_sha256_ctx ctx;
    ag_sha256_init(&ctx);
    ag_sha256_update(&ctx, data, len);
    ag_sha256_final(&ctx, digest);
}

/* ════════════════════════════════════════════════════════════════════════
   辅助：小端读取
   ════════════════════════════════════════════════════════════════════════ */

/* 从缓冲区读取 uint16 小端值 */
static uint16_t ag_le16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

/* 从缓冲区读取 uint32 小端值 */
static uint32_t ag_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* 从缓冲区读取 uint64 小端值 */
static uint64_t ag_le64(const uint8_t *p) {
    return (uint64_t)ag_le32(p) | ((uint64_t)ag_le32(p + 4) << 32);
}

/* ════════════════════════════════════════════════════════════════════════
   文件读取封装（POSIX I/O）
   ════════════════════════════════════════════════════════════════════════ */

/* 从文件指定偏移处读取指定长度的数据 */
static int ag_read_at(int fd, off_t offset, void *buf, size_t len) {
    size_t done = 0;
    if (lseek(fd, offset, SEEK_SET) != offset) return 0;
    while (done < len) {
        ssize_t n = read(fd, (uint8_t *)buf + done, len - done);
        if (n <= 0) return 0;
        done += (size_t)n;
    }
    return 1;
}

/* ════════════════════════════════════════════════════════════════════════
   ZIP 解析：定位 EOCD 与 Central Directory 偏移
   ════════════════════════════════════════════════════════════════════════ */

/* 从文件末尾搜索 EOCD 签名并返回 Central Directory 偏移 */
static int ag_find_cd(int fd, off_t file_size, uint32_t *cd_offset) {
    size_t search_size = 65557;
    off_t start;
    uint8_t *buf;
    int i;

    if ((size_t)file_size < search_size) search_size = (size_t)file_size;
    buf = (uint8_t *)malloc(search_size);
    if (!buf) return 0;

    start = file_size - (off_t)search_size;
    if (!ag_read_at(fd, start, buf, search_size)) { free(buf); return 0; }

    for (i = (int)search_size - 22; i >= 0; i--) {
        if (buf[i] == 0x50 && buf[i+1] == 0x4b &&
            buf[i+2] == 0x05 && buf[i+3] == 0x06) {
            *cd_offset = ag_le32(buf + i + 16);
            free(buf);
            return 1;
        }
    }
    free(buf);
    return 0;
}

/* ════════════════════════════════════════════════════════════════════════
   V2 签名提取：APK Signing Block -> V2 signer -> certificate DER
   ════════════════════════════════════════════════════════════════════════ */

/**
 * 从 APK Signing Block 的 V2 签名中提取第一个证书的 DER 数据。
 * 返回 malloc 分配的缓冲区（调用方负责 free），cert_len 输出证书长度。
 */
static uint8_t *ag_v2_cert(int fd, uint32_t cd_offset, size_t *cert_len) {
    uint8_t magic_buf[16], sz_buf[8];
    uint64_t block_size;
    off_t block_start, pairs_start, pairs_end, pos;

    if (cd_offset < 24) return NULL;
    if (!ag_read_at(fd, (off_t)cd_offset - 16, magic_buf, 16)) return NULL;
    if (memcmp(magic_buf, "APK Sig Block 42", 16) != 0) {
        AG_LOG("V2: magic not found");
        return NULL;
    }

    if (!ag_read_at(fd, (off_t)cd_offset - 24, sz_buf, 8)) return NULL;
    block_size = ag_le64(sz_buf);
    if (block_size > (uint64_t)cd_offset || block_size < 32) return NULL;

    block_start = (off_t)cd_offset - 8 - (off_t)block_size;
    pairs_start = block_start + 8;
    pairs_end = (off_t)cd_offset - 24;

    pos = pairs_start;
    while (pos + 12 <= pairs_end) {
        uint8_t hdr[12];
        uint64_t pair_size;
        uint32_t id;

        if (!ag_read_at(fd, pos, hdr, 12)) return NULL;
        pair_size = ag_le64(hdr);
        id = ag_le32(hdr + 8);

        if (id == 0x7109871a) {
            size_t value_size = (size_t)(pair_size - 4);
            size_t off, signed_data_end;
            uint32_t signers_len, signer_len, signed_data_len;
            uint32_t digests_len, certs_len, c_len;
            uint8_t *value, *cert;

            if (value_size < 12 || value_size > 10 * 1024 * 1024) return NULL;
            value = (uint8_t *)malloc(value_size);
            if (!value) return NULL;
            if (!ag_read_at(fd, pos + 12, value, value_size)) { free(value); return NULL; }

            off = 0;

            if (off + 4 > value_size) { free(value); return NULL; }
            signers_len = ag_le32(value + off); off += 4;
            (void)signers_len;

            if (off + 4 > value_size) { free(value); return NULL; }
            signer_len = ag_le32(value + off); off += 4;
            (void)signer_len;

            if (off + 4 > value_size) { free(value); return NULL; }
            signed_data_len = ag_le32(value + off); off += 4;
            signed_data_end = off + signed_data_len;

            if (off + 4 > value_size) { free(value); return NULL; }
            digests_len = ag_le32(value + off); off += 4;
            off += digests_len;

            if (off + 4 > signed_data_end) { free(value); return NULL; }
            certs_len = ag_le32(value + off); off += 4;
            (void)certs_len;

            if (off + 4 > signed_data_end) { free(value); return NULL; }
            c_len = ag_le32(value + off); off += 4;
            if (off + c_len > value_size) { free(value); return NULL; }

            cert = (uint8_t *)malloc(c_len);
            if (!cert) { free(value); return NULL; }
            memcpy(cert, value + off, c_len);
            *cert_len = c_len;
            free(value);
            AG_LOG("V2: extracted cert (%u bytes)", c_len);
            return cert;
        }

        pos += 8 + (off_t)pair_size;
    }

    AG_LOG("V2: id 0x7109871a not found");
    return NULL;
}

/* ════════════════════════════════════════════════════════════════════════
   V1 签名回退：Central Directory -> META-INF .RSA -> PKCS#7 -> X.509
   ════════════════════════════════════════════════════════════════════════ */

/**
 * 解析 ASN.1 TLV 标签和长度。
 * 返回 body 起始偏移，body_len 输出 body 长度；失败返回 0。
 */
static size_t ag_asn1_tl(const uint8_t *buf, size_t buf_len, size_t off,
                         uint8_t *tag_out, size_t *body_len) {
    int num_bytes, i;
    uint8_t first;
    size_t len;

    if (off >= buf_len) return 0;
    *tag_out = buf[off++];
    if (off >= buf_len) return 0;

    first = buf[off++];
    if (first < 0x80) {
        *body_len = first;
    } else {
        num_bytes = first & 0x7f;
        if (num_bytes == 0 || num_bytes > 4 || off + (size_t)num_bytes > buf_len) return 0;
        len = 0;
        for (i = 0; i < num_bytes; i++) {
            len = (len << 8) | buf[off++];
        }
        *body_len = len;
    }
    return off;
}

/**
 * 从 PKCS#7 SignedData DER 中提取第一个 X.509 证书。
 * 返回指向 der 缓冲区内部的指针和长度，不分配内存。
 */
static const uint8_t *ag_pkcs7_cert(const uint8_t *der, size_t der_len, size_t *cert_len) {
    size_t off = 0, body_len, cert_start;
    uint8_t tag;

    off = ag_asn1_tl(der, der_len, off, &tag, &body_len);
    if (!off || tag != 0x30) return NULL;

    off = ag_asn1_tl(der, der_len, off, &tag, &body_len);
    if (!off || tag != 0x06) return NULL;
    off += body_len;

    off = ag_asn1_tl(der, der_len, off, &tag, &body_len);
    if (!off || tag != 0xa0) return NULL;

    off = ag_asn1_tl(der, der_len, off, &tag, &body_len);
    if (!off || tag != 0x30) return NULL;

    off = ag_asn1_tl(der, der_len, off, &tag, &body_len);
    if (!off || tag != 0x02) return NULL;
    off += body_len;

    off = ag_asn1_tl(der, der_len, off, &tag, &body_len);
    if (!off || tag != 0x31) return NULL;
    off += body_len;

    off = ag_asn1_tl(der, der_len, off, &tag, &body_len);
    if (!off || tag != 0x30) return NULL;
    off += body_len;

    off = ag_asn1_tl(der, der_len, off, &tag, &body_len);
    if (!off || tag != 0xa0) return NULL;

    cert_start = off;
    off = ag_asn1_tl(der, der_len, off, &tag, &body_len);
    if (!off || tag != 0x30) return NULL;

    *cert_len = off + body_len - cert_start;
    return der + cert_start;
}

/**
 * 从 Central Directory 中搜索 META-INF 下的 .RSA 文件并提取 X.509 证书 DER。
 * 返回 malloc 分配的缓冲区，cert_len 输出长度。
 */
static uint8_t *ag_v1_cert(int fd, off_t file_size, uint32_t cd_offset, size_t *cert_len) {
    size_t cd_size = (size_t)(file_size - cd_offset);
    size_t pos;
    uint8_t *cd_buf;

    if (cd_size > 2 * 1024 * 1024) cd_size = 2 * 1024 * 1024;
    cd_buf = (uint8_t *)malloc(cd_size);
    if (!cd_buf) return NULL;
    if (!ag_read_at(fd, cd_offset, cd_buf, cd_size)) { free(cd_buf); return NULL; }

    pos = 0;
    while (pos + 46 <= cd_size) {
        uint16_t name_len, extra_len, comment_len, comp_method;
        uint32_t comp_size, local_hdr_off;
        char *name;
        int is_rsa;

        if (cd_buf[pos] != 0x50 || cd_buf[pos+1] != 0x4b ||
            cd_buf[pos+2] != 0x01 || cd_buf[pos+3] != 0x02) break;

        name_len    = ag_le16(cd_buf + pos + 28);
        extra_len   = ag_le16(cd_buf + pos + 30);
        comment_len = ag_le16(cd_buf + pos + 32);
        comp_method = ag_le16(cd_buf + pos + 10);
        comp_size   = ag_le32(cd_buf + pos + 20);
        local_hdr_off = ag_le32(cd_buf + pos + 42);

        if (pos + 46 + name_len > cd_size) break;

        name = (char *)(cd_buf + pos + 46);
        is_rsa = 0;
        if (name_len > 10 && memcmp(name, "META-INF/", 9) == 0 && name_len >= 4 &&
            name[name_len-4] == '.' &&
            (name[name_len-3] == 'R' || name[name_len-3] == 'r') &&
            (name[name_len-2] == 'S' || name[name_len-2] == 's') &&
            (name[name_len-1] == 'A' || name[name_len-1] == 'a')) {
            is_rsa = 1;
        }

        if (is_rsa && comp_method == 0) {
            uint8_t lfh[30];
            uint16_t lfh_name_len, lfh_extra_len;
            off_t data_off;
            uint8_t *rsa_data;
            size_t c_len;
            const uint8_t *cert_ptr;

            AG_LOG("V1: found %.*s (STORED, %u bytes)", name_len, name, comp_size);

            if (!ag_read_at(fd, local_hdr_off, lfh, 30)) { free(cd_buf); return NULL; }
            lfh_name_len  = ag_le16(lfh + 26);
            lfh_extra_len = ag_le16(lfh + 28);
            data_off = local_hdr_off + 30 + lfh_name_len + lfh_extra_len;

            rsa_data = (uint8_t *)malloc(comp_size);
            if (!rsa_data) { free(cd_buf); return NULL; }
            if (!ag_read_at(fd, data_off, rsa_data, comp_size)) {
                free(rsa_data); free(cd_buf); return NULL;
            }

            cert_ptr = ag_pkcs7_cert(rsa_data, comp_size, &c_len);
            if (cert_ptr) {
                uint8_t *cert = (uint8_t *)malloc(c_len);
                if (cert) {
                    memcpy(cert, cert_ptr, c_len);
                    *cert_len = c_len;
                }
                free(rsa_data);
                free(cd_buf);
                AG_LOG("V1: extracted cert (%zu bytes)", c_len);
                return cert;
            }
            free(rsa_data);
        }

        pos += 46 + name_len + extra_len + comment_len;
    }

    free(cd_buf);
    AG_LOG("V1: no suitable RSA entry found");
    return NULL;
}

/* ════════════════════════════════════════════════════════════════════════
   指纹校验
   ════════════════════════════════════════════════════════════════════════ */

/* 混淆后的证书指纹：原始 SHA-256 每字节与位置密钥 (i*0x6D+0x3F)&0xFF 异或 */
static const uint8_t AG_OBF_FP[32] = {
    0xf2, 0xfe, 0xe4, 0x67, 0x1c, 0x62, 0xb7, 0x58,
    0x93, 0xc5, 0x6a, 0x26, 0xca, 0x35, 0x25, 0x87,
    0x2c, 0x38, 0x3b, 0x0d, 0x2b, 0x87, 0xaf, 0x61,
    0x53, 0xdc, 0x4e, 0xb5, 0x7a, 0x61, 0xbe, 0xbf,
};

/* 常数时间解混淆并比较摘要 */
static int ag_verify_fp(const uint8_t *digest) {
    volatile uint8_t diff = 0;
    size_t i;
    for (i = 0; i < 32; i++) {
        uint8_t key = (uint8_t)((i * 0x6D + 0x3F) & 0xFF);
        diff |= digest[i] ^ AG_OBF_FP[i] ^ key;
    }
    return diff == 0;
}

/* 将 32 字节摘要格式化为十六进制字符串 */
static void ag_hex(const uint8_t *data, size_t len, char *out) {
    static const char tbl[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < len; i++) {
        out[i*2]   = tbl[data[i] >> 4];
        out[i*2+1] = tbl[data[i] & 0x0f];
    }
    out[len*2] = '\0';
}

/* ════════════════════════════════════════════════════════════════════════
   内部校验：解析 APK 并比对指纹
   ════════════════════════════════════════════════════════════════════════ */

/* 对指定 APK 文件执行签名校验，返回 1=匹配 0=不匹配 */
static int ag_do_verify(const char *path) {
    int fd, match;
    off_t file_size;
    uint32_t cd_offset = 0;
    size_t cert_len = 0;
    uint8_t *cert;
    uint8_t digest[32];
    char hex_buf[65];

    fd = open(path, O_RDONLY);
    if (fd < 0) { AG_LOG("cannot open APK"); return 0; }

    file_size = lseek(fd, 0, SEEK_END);
    if (file_size <= 0) { close(fd); return 0; }

    if (!ag_find_cd(fd, file_size, &cd_offset)) {
        AG_LOG("EOCD not found");
        close(fd);
        return 0;
    }
    AG_LOG("CD offset: %u", cd_offset);

    cert = ag_v2_cert(fd, cd_offset, &cert_len);
    if (!cert) {
        AG_LOG("V2 not found, trying V1");
        cert = ag_v1_cert(fd, file_size, cd_offset, &cert_len);
    }
    close(fd);

    if (!cert) { AG_LOG("no certificate extracted"); return 0; }

    ag_sha256(cert, cert_len, digest);
    free(cert);

    ag_hex(digest, 32, hex_buf);
    AG_LOG("cert fingerprint: %s", hex_buf);

    match = ag_verify_fp(digest);
    AG_LOG("signature verify: %s", match ? "PASS" : "FAIL");
    return match;
}

/* ════════════════════════════════════════════════════════════════════════
   SO 自动入口：constructor 在 dlopen 时自动执行，无需 JNI
   ════════════════════════════════════════════════════════════════════════ */

/* 后台线程：sleep 随机秒数后静默终止进程 */
static void *ag_delayed_exit_thread(void *arg) {
    unsigned int secs = *(unsigned int *)arg;
    free(arg);
    sleep(secs);
    _exit(0);
    return NULL;
}

/* 启动延迟退出：从 /dev/urandom 取随机值，10-20 秒后终止 */
static void ag_schedule_exit(void) {
    pthread_t tid;
    unsigned int *secs;
    uint32_t rnd = 0;
    int ufd = open("/dev/urandom", O_RDONLY);
    if (ufd >= 0) {
        read(ufd, &rnd, sizeof(rnd));
        close(ufd);
    }
    secs = (unsigned int *)malloc(sizeof(unsigned int));
    if (!secs) { _exit(0); return; }
    *secs = 10 + (rnd % 11);
    pthread_create(&tid, NULL, ag_delayed_exit_thread, secs);
    pthread_detach(tid);
}

/* 从 /proc/self/maps 搜索当前进程加载的 APK 路径 */
static int ag_find_apk(char *out, size_t out_size) {
    FILE *f;
    char line[1024];

    f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    while (fgets(line, sizeof(line), f)) {
        char *p = strstr(line, "/data/app/");
        char *end;
        size_t len;
        if (!p) continue;
        end = p;
        while (*end && *end != '\n' && *end != ' ') end++;
        len = (size_t)(end - p);
        if (len > 4 && memcmp(end - 4, ".apk", 4) == 0 && len < out_size) {
            memcpy(out, p, len);
            out[len] = '\0';
            fclose(f);
            return 1;
        }
    }
    fclose(f);
    return 0;
}

/* SO 加载时自动执行签名校验，失败则延迟随机秒数后静默终止 */
__attribute__((constructor))
static void ag_guard_init(void) {
    char apk_path[512];
    if (!ag_find_apk(apk_path, sizeof(apk_path))) {
        ag_schedule_exit();
        return;
    }
    AG_LOG("APK path: %s", apk_path);
    if (!ag_do_verify(apk_path)) {
        ag_schedule_exit();
    }
}
