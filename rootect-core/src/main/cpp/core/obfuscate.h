#pragma once

// Compile-time string hiding.
//
// A detector must not ship the paths it probes as bare literals — an attacker dumps the
// binary, reads the list, and hides exactly those. ROOTECT_HIDE XOR-encrypts at compile
// time so only ciphertext reaches .rodata.
//
// Whether the plaintext really stays out is a quality-of-implementation matter, not a
// language guarantee — scripts/check-no-plaintext.sh is the gate that proves it.

#include <cstddef>
#include <utility>

#ifndef ROOTECT_OBFUSCATION_SEED
#define ROOTECT_OBFUSCATION_SEED 0x00000000u
#endif

static_assert(__cplusplus >= 201703L,
              "ROOTECT_HIDE needs C++17 guaranteed copy elision: Hidden is deliberately "
              "neither copyable nor movable, yet is returned by value.");

namespace rootect::obf {

// The build seed is a diversity input, not a secret. A different value changes the
// keystream at every call site so a patch made for one distribution does not transfer
// byte-for-byte to another distribution.
constexpr unsigned kBuildSeed = static_cast<unsigned>(ROOTECT_OBFUSCATION_SEED);

constexpr unsigned mix_build_seed(unsigned value) {
    value ^= value >> 16;
    value *= 0x7FEB352Du;
    value ^= value >> 15;
    value *= 0x846CA68Bu;
    value ^= value >> 16;
    return value;
}

// Keystream byte for position `i`, so repeated characters do not encrypt alike.
constexpr char key_at(std::size_t i, unsigned seed) {
    unsigned k = seed * 2654435761u + static_cast<unsigned>(i) * 40503u + 0x9E37u;
    return static_cast<char>((k >> 16) & 0xFF);
}

// Holds the encrypted bytes. Built at compile time, so the plaintext is never emitted.
template <std::size_t N, unsigned Seed, typename = std::make_index_sequence<N>>
class Cipher;

template <std::size_t N, unsigned Seed, std::size_t... I>
class Cipher<N, Seed, std::index_sequence<I...>> {
public:
    constexpr explicit Cipher(const char* s)
        : enc_{static_cast<char>(s[I] ^ key_at(I, Seed))...} {}

    // Writes the plaintext into `out`, which must hold N bytes.
    void decode(char* out) const {
        for (std::size_t i = 0; i < N; ++i) {
            // Optimisation barrier. Without it -O2 folds the encrypt/decrypt round-trip and
            // re-materialises the plaintext as a constant, defeating the whole point.
            char e = enc_[i];
            __asm__ volatile("" : "+r"(e));
            out[i] = static_cast<char>(e ^ key_at(i, Seed));
        }
    }

private:
    char enc_[N];
};

// Decrypted plaintext with a scoped lifetime, wiped on destruction. Non-copyable so the
// cleartext cannot outlive the wipe.
template <std::size_t N>
class Hidden {
public:
    template <unsigned Seed>
    explicit Hidden(const Cipher<N, Seed>& c) { c.decode(buf_); }

    Hidden(const Hidden&) = delete;
    Hidden(Hidden&&) = delete;

    ~Hidden() {
        volatile char* p = buf_;
        for (std::size_t i = 0; i < N; ++i) p[i] = 0;
    }

    const char* c_str() const { return buf_; }

private:
    char buf_[N];
};

} // namespace rootect::obf

// Yields a scoped Hidden holding the decrypted literal. __COUNTER__ gives each call site its
// own key. The build seed makes those keys differ across source-built distributions.
#define ROOTECT_HIDE(lit)                                                             \
    ([] {                                                                             \
        constexpr unsigned _seed =                                                    \
            ((static_cast<unsigned>(__COUNTER__) * 2246822519u) ^ 0x27d4eb2fu) ^      \
            ::rootect::obf::mix_build_seed(::rootect::obf::kBuildSeed);               \
        static constexpr ::rootect::obf::Cipher<sizeof(lit), _seed> _c(lit);          \
        return ::rootect::obf::Hidden<sizeof(lit)>(_c);                               \
    }())
