#pragma once

// Compile-time string hiding.
//
// A detector that greps the filesystem for a root path must not ship that path as a bare
// literal — an attacker dumps the binary, reads the list, and hides exactly those paths.
// ROOTECT_HIDE XOR-encrypts a literal at compile time so only ciphertext lands in .rodata,
// decrypts it into a stack buffer on use, and wipes that buffer when it goes out of scope.
//
// Whether the plaintext truly stays out of the binary is a quality-of-implementation
// matter, not a language guarantee — scripts/check-no-plaintext.sh is the gate that proves it.

#include <cstddef>
#include <utility>

static_assert(__cplusplus >= 201703L,
              "ROOTECT_HIDE needs C++17 guaranteed copy elision: Hidden is deliberately "
              "neither copyable nor movable, yet is returned by value.");

namespace rootect::obf {

// Position-dependent keystream, so repeated characters don't encrypt alike.
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

    void decode(char* out) const {
        for (std::size_t i = 0; i < N; ++i) {
            // Optimisation barrier. Without it, -O2 folds this whole encrypt→decrypt
            // round-trip at compile time and re-materialises the plaintext as a constant,
            // defeating the point. Forcing each byte through opaque asm keeps enc_ as
            // ciphertext in .rodata and the XOR a genuine runtime operation.
            char e = enc_[i];
            __asm__ volatile("" : "+r"(e));
            out[i] = static_cast<char>(e ^ key_at(i, Seed));
        }
    }

private:
    char enc_[N];
};

// Decrypted plaintext with a scoped lifetime — wiped on destruction. Non-copyable so the
// cleartext can't quietly outlive the wipe.
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

// Yields a scoped Hidden holding the decrypted literal. __COUNTER__ gives each call site a
// distinct key, so identical strings don't produce identical ciphertext.
#define ROOTECT_HIDE(lit)                                                             \
    ([] {                                                                             \
        constexpr unsigned _seed =                                                    \
            (static_cast<unsigned>(__COUNTER__) * 2246822519u) ^ 0x27d4eb2fu;         \
        static constexpr ::rootect::obf::Cipher<sizeof(lit), _seed> _c(lit);          \
        return ::rootect::obf::Hidden<sizeof(lit)>(_c);                               \
    }())
