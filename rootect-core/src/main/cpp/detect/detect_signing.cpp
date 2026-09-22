#include "detect/detectors.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "core/obfuscate.h"
#include "core/proc.h"
#include "core/syscalls.h"

namespace rootect {
namespace {

constexpr uint32_t kV2BlockId = 0x7109871Au;
constexpr uint32_t kV3BlockId = 0xF05368C0u;
constexpr uint32_t kV31BlockId = 0x1B93AD61u;
constexpr unsigned kDigestLen = 32;
constexpr unsigned kScratchLen = 22 + 65535;

uint32_t load32(const unsigned char* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t load64(const unsigned char* p) {
    return static_cast<uint64_t>(load32(p)) |
           (static_cast<uint64_t>(load32(p + 4)) << 32);
}

struct Sha256 {
    uint32_t state[8];
    uint64_t bits = 0;
    unsigned char block[64] = {0};
    unsigned filled = 0;

    Sha256() {
        state[0] = 0x6A09E667u; state[1] = 0xBB67AE85u;
        state[2] = 0x3C6EF372u; state[3] = 0xA54FF53Au;
        state[4] = 0x510E527Fu; state[5] = 0x9B05688Cu;
        state[6] = 0x1F83D9ABu; state[7] = 0x5BE0CD19u;
    }

    static uint32_t rotr(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }

    void compress(const unsigned char* p) {
        static const uint32_t k[64] = {
            0x428A2F98u, 0x71374491u, 0xB5C0FBCFu, 0xE9B5DBA5u, 0x3956C25Bu, 0x59F111F1u,
            0x923F82A4u, 0xAB1C5ED5u, 0xD807AA98u, 0x12835B01u, 0x243185BEu, 0x550C7DC3u,
            0x72BE5D74u, 0x80DEB1FEu, 0x9BDC06A7u, 0xC19BF174u, 0xE49B69C1u, 0xEFBE4786u,
            0x0FC19DC6u, 0x240CA1CCu, 0x2DE92C6Fu, 0x4A7484AAu, 0x5CB0A9DCu, 0x76F988DAu,
            0x983E5152u, 0xA831C66Du, 0xB00327C8u, 0xBF597FC7u, 0xC6E00BF3u, 0xD5A79147u,
            0x06CA6351u, 0x14292967u, 0x27B70A85u, 0x2E1B2138u, 0x4D2C6DFCu, 0x53380D13u,
            0x650A7354u, 0x766A0ABBu, 0x81C2C92Eu, 0x92722C85u, 0xA2BFE8A1u, 0xA81A664Bu,
            0xC24B8B70u, 0xC76C51A3u, 0xD192E819u, 0xD6990624u, 0xF40E3585u, 0x106AA070u,
            0x19A4C116u, 0x1E376C08u, 0x2748774Cu, 0x34B0BCB5u, 0x391C0CB3u, 0x4ED8AA4Au,
            0x5B9CCA4Fu, 0x682E6FF3u, 0x748F82EEu, 0x78A5636Fu, 0x84C87814u, 0x8CC70208u,
            0x90BEFFFAu, 0xA4506CEBu, 0xBEF9A3F7u, 0xC67178F2u,
        };
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(p[i * 4]) << 24) |
                   (static_cast<uint32_t>(p[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(p[i * 4 + 2]) << 8) |
                   static_cast<uint32_t>(p[i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = h + s1 + ch + k[i] + w[i];
            uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + s0 + maj;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

    void absorb(const unsigned char* data, unsigned long len) {
        while (len > 0) {
            unsigned take = 64 - filled;
            if (take > len) take = static_cast<unsigned>(len);
            for (unsigned i = 0; i < take; ++i) block[filled + i] = data[i];
            filled += take;
            data += take;
            len -= take;
            if (filled == 64) {
                compress(block);
                filled = 0;
            }
        }
    }

    void update(const unsigned char* data, unsigned long len) {
        bits += static_cast<uint64_t>(len) * 8;
        absorb(data, len);
    }

    void finish(unsigned char out[32]) {
        unsigned char pad[64] = {0x80};
        unsigned used = filled;
        unsigned pad_len = used < 56 ? 56 - used : 120 - used;
        absorb(pad, pad_len);
        unsigned char lenb[8];
        for (int i = 0; i < 8; ++i) lenb[i] = static_cast<unsigned char>(bits >> (56 - 8 * i));
        absorb(lenb, 8);
        for (int i = 0; i < 8; ++i) {
            out[i * 4] = static_cast<unsigned char>(state[i] >> 24);
            out[i * 4 + 1] = static_cast<unsigned char>(state[i] >> 16);
            out[i * 4 + 2] = static_cast<unsigned char>(state[i] >> 8);
            out[i * 4 + 3] = static_cast<unsigned char>(state[i]);
        }
    }
};

bool read_exact(int fd, void* buf, unsigned long n, long long off) {
    auto* out = static_cast<unsigned char*>(buf);
    unsigned long got = 0;
    while (got < n) {
        long nread = rt_pread(fd, out + got, n - got, off + static_cast<long long>(got));
        if (nread <= 0) return false;
        got += static_cast<unsigned long>(nread);
    }
    return true;
}

bool find_eocd(int fd, long long size, long long& eocd, unsigned char* buf) {
    constexpr unsigned kTail = 22;
    constexpr unsigned kMaxComment = 65535;
    unsigned long window = kTail + kMaxComment;
    if (static_cast<unsigned long long>(size) < window) window = static_cast<unsigned long>(size);
    if (window < kTail) return false;

    long long start = size - static_cast<long long>(window);
    if (!read_exact(fd, buf, window, start)) return false;
    for (unsigned long i = window - kTail + 1; i-- > 0;) {
        if (load32(buf + i) != 0x06054B50u) continue;
        unsigned comment = buf[i + 20] | (static_cast<unsigned>(buf[i + 21]) << 8);
        if (i + kTail + comment != window) continue;
        eocd = start + static_cast<long long>(i);
        return true;
    }
    return false;
}

bool in_range(const unsigned char* base, unsigned long size, unsigned long off, uint32_t len) {
    return off <= size && len <= size - off;
}

bool take_cert(const unsigned char* base, unsigned long certs_end, unsigned long& off,
               unsigned char digest[32]) {
    if (!in_range(base, certs_end, off, 4)) return false;
    uint32_t len = load32(base + off);
    off += 4;
    if (len == 0 || !in_range(base, certs_end, off, len)) return false;
    Sha256 sha;
    sha.update(base + off, len);
    sha.finish(digest);
    off += len;
    return true;
}

// Lengths are the payload only. Certificates sit in signed data, after digests.
bool hash_certs(const unsigned char* base, unsigned long size, unsigned long signer_off,
                uint32_t signer_len, unsigned char digest[32], bool v3, int sdk,
                bool& applicable) {
    unsigned long end = signer_off + signer_len;
    if (!in_range(base, size, signer_off, 4)) return false;
    uint32_t signed_len = load32(base + signer_off);
    unsigned long signed_off = signer_off + 4;
    if (signed_len < 12 || !in_range(base, end, signed_off, signed_len)) return false;
    unsigned long signed_end = signed_off + signed_len;

    if (!in_range(base, signed_end, signed_off, 4)) return false;
    uint32_t digests_len = load32(base + signed_off);
    unsigned long cursor = signed_off + 4;
    if (!in_range(base, signed_end, cursor, digests_len)) return false;
    cursor += digests_len;

    if (!in_range(base, signed_end, cursor, 4)) return false;
    uint32_t certs_len = load32(base + cursor);
    cursor += 4;
    if (certs_len < 5 || !in_range(base, signed_end, cursor, certs_len)) return false;
    unsigned long certs_end = cursor + certs_len;
    if (!take_cert(base, certs_end, cursor, digest)) return false;
    while (cursor < certs_end) {
        if (!in_range(base, certs_end, cursor, 4)) return false;
        uint32_t len = load32(base + cursor);
        cursor += 4;
        if (len == 0 || !in_range(base, certs_end, cursor, len)) return false;
        cursor += len;
    }
    if (v3) {
        // Signed copy of the SDK range; the platform selects by the outer copy below.
        if (!in_range(base, signed_end, cursor, 8)) return false;
        cursor += 8;
    }
    if (!in_range(base, signed_end, cursor, 4)) return false;
    uint32_t attrs_len = load32(base + cursor);
    cursor += 4;
    if (!in_range(base, signed_end, cursor, attrs_len)) return false;

    cursor = signed_end;
    applicable = true;
    if (v3) {
        // The platform picks a v3 signer by this unsigned range and skips the rest unverified.
        if (!in_range(base, end, cursor, 8)) return false;
        uint32_t min_sdk = load32(base + cursor);
        uint32_t max_sdk = load32(base + cursor + 4);
        applicable = sdk >= 0 && static_cast<uint32_t>(sdk) >= min_sdk &&
                     static_cast<uint32_t>(sdk) <= max_sdk;
        cursor += 8;
    }
    if (!in_range(base, end, cursor, 4)) return false;
    uint32_t sigs_len = load32(base + cursor);
    cursor += 4;
    if (!in_range(base, end, cursor, sigs_len)) return false;
    cursor += sigs_len;
    if (!in_range(base, end, cursor, 4)) return false;
    uint32_t key_len = load32(base + cursor);
    cursor += 4;
    if (!in_range(base, end, cursor, key_len) || cursor + key_len != end) return false;
    return true;
}

bool walk_scheme(const unsigned char* value, unsigned long size,
                 unsigned char digest[32], bool v3, int sdk, bool& found) {
    if (!in_range(value, size, 0, 4)) return false;
    uint32_t seq_len = load32(value);
    if (seq_len < 8 || 4u + seq_len != size) return false;
    unsigned long off = 4;
    unsigned long seq_end = 4 + seq_len;
    found = false;
    while (off < seq_end) {
        if (!in_range(value, seq_end, off, 4)) return false;
        uint32_t signer_len = load32(value + off);
        off += 4;
        if (signer_len < 16 || !in_range(value, seq_end, off, signer_len)) return false;
        unsigned char candidate[32];
        bool applicable = false;
        if (!hash_certs(value, size, off, signer_len, candidate, v3, sdk, applicable)) return false;
        if (applicable) {
            // Multiple current signers need a platform-aligned comparison; report unknown.
            if (found) return false;
            for (unsigned i = 0; i < 32; ++i) digest[i] = candidate[i];
            found = true;
        }
        off += signer_len;
    }
    return true;
}

bool signing_digest(int fd, long long eocd, unsigned char digest[32],
                    unsigned char* value, int sdk) {
    unsigned char eocd_head[20];
    if (!read_exact(fd, eocd_head, sizeof(eocd_head), eocd)) return false;
    long long central = load32(eocd_head + 16);
    if (central < 32) return false;

    unsigned char footer[24];
    if (!read_exact(fd, footer, sizeof(footer), central - 24)) return false;
    auto magic = ROOTECT_HIDE("APK Sig Block 42");
    for (unsigned i = 0; i < 16; ++i) {
        if (footer[8 + i] != static_cast<unsigned char>(magic.c_str()[i])) return false;
    }
    uint64_t block_size = load64(footer);
    if (block_size < 32 || block_size > static_cast<uint64_t>(central)) return false;
    long long block_off = central - static_cast<long long>(block_size + 8);

    unsigned char header[8];
    if (!read_exact(fd, header, sizeof(header), block_off)) return false;
    if (load64(header) != block_size) return false;

    long long pairs_off = block_off + 8;
    uint64_t pairs_len = block_size - 24;
    unsigned char pair_head[12];
    unsigned char v31[32];
    unsigned char v3[32];
    unsigned char v2[32];
    bool saw_v31 = false;
    bool saw_v3 = false;
    bool saw_v2 = false;

    while (pairs_len >= 12) {
        if (!read_exact(fd, pair_head, sizeof(pair_head), pairs_off)) return false;
        uint64_t pair_len = load64(pair_head);
        if (pair_len < 4 || pair_len > pairs_len - 8) return false;
        uint32_t id = load32(pair_head + 8);
        uint64_t value_len = pair_len - 4;
        if ((id == kV31BlockId || id == kV3BlockId || id == kV2BlockId) &&
            value_len > 0 && value_len <= 64u * 1024u) {
            bool ok = read_exact(fd, value, static_cast<unsigned long>(value_len), pairs_off + 12);
            if (ok && id == kV31BlockId && sdk >= 33) {
                ok = walk_scheme(value, static_cast<unsigned long>(value_len), v31, true, sdk,
                                 saw_v31);
            } else if (ok && id == kV3BlockId && sdk >= 28) {
                ok = walk_scheme(value, static_cast<unsigned long>(value_len), v3, true, sdk,
                                 saw_v3);
            } else if (ok && id == kV2BlockId) {
                ok = walk_scheme(value, static_cast<unsigned long>(value_len), v2, false, sdk,
                                 saw_v2);
            }
            for (uint64_t i = 0; i < value_len; ++i) value[i] = 0;
            if (!ok) return false;
        } else if (id == kV31BlockId || id == kV3BlockId || id == kV2BlockId) {
            return false;
        }
        uint64_t step = 8 + pair_len;
        pairs_off += static_cast<long long>(step);
        pairs_len -= step;
    }
    if (pairs_len != 0) return false;

    const unsigned char* chosen = saw_v31 ? v31 : saw_v3 ? v3 : saw_v2 ? v2 : nullptr;
    if (chosen == nullptr) return false;
    for (unsigned b = 0; b < kDigestLen; ++b) digest[b] = chosen[b];
    return true;
}

int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

} // namespace

int signing_matches(const char* apk_path, const char* expected_hex, int sdk) {
    unsigned char expected[kDigestLen];
    unsigned filled = 0;
    int high = -1;
    for (const char* p = expected_hex; *p; ++p) {
        if (*p == ':' || *p == ' ') continue;
        int nibble = hex_nibble(*p);
        if (nibble < 0 || filled >= kDigestLen) return 1;
        if (high < 0) {
            high = nibble;
        } else {
            expected[filled++] = static_cast<unsigned char>((high << 4) | nibble);
            high = -1;
        }
    }
    if (filled != kDigestLen || high >= 0) return 1;

    int fd = rt_openat(apk_path, O_RDONLY);
    if (fd < 0) return -1;
    long long size = rt_lseek(fd, 0, /*SEEK_END*/ 2);
    if (size < 0) {
        rt_close(fd);
        return -1;
    }

    auto* scratch = static_cast<unsigned char*>(malloc(kScratchLen));
    if (scratch == nullptr) {
        rt_close(fd);
        return -1;
    }
    long long eocd = 0;
    unsigned char digest[kDigestLen];
    bool ok = find_eocd(fd, size, eocd, scratch) &&
              signing_digest(fd, eocd, digest, scratch, sdk);
    free(scratch);
    rt_close(fd);
    if (!ok) return -1;

    for (unsigned b = 0; b < kDigestLen; ++b) {
        if (digest[b] != expected[b]) return 1;
    }
    return 0;
}

} // namespace rootect
