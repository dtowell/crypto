#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <string>
#include <memory>
#include <cstddef>
#include <immintrin.h>
#include <cassert>
#include <cpuid.h>

#ifndef _CRYPTO_H
#define _CRYPTO_H

namespace crypto {
    using buffer_t = std::vector<uint8_t>;
    using block_t = __m128i;

    bool read_file(std::string filename,buffer_t &buffer);
    bool write_file(std::string filename,const buffer_t &buffer);

    bool rand_rdrand(size_t bytes,buffer_t &buffer);

    void encode_base64(const buffer_t &plain,std::string &encoded);
    void decode_base64(const std::string &encoded,buffer_t &buffer);

    bool encode_aes_ecb(const buffer_t &clear,block_t key,buffer_t &cipher);
    bool decode_aes_ecb(const buffer_t &cipher,block_t key,buffer_t &clear);

    bool encode_aes_cbc(const buffer_t &clear,block_t key,block_t iv,buffer_t &cipher);
    bool decode_aes_cbc(const buffer_t &cipher,block_t key,block_t iv,buffer_t &clear);

    bool hash_sha256(const buffer_t &clear,buffer_t &hash);
    bool hash_sha512(const buffer_t &clear,buffer_t &hash);
    bool hash_sha512_256(const buffer_t &clear,buffer_t &hash);

    struct rsa_private_t {
        uint64_t    p,q;
        uint64_t    e,d;
    };

    struct rsa_public_t {
        uint64_t    e,n;
    };

    bool rsa_generate(rsa_private_t &key);
    bool rsa_publish(const rsa_private_t &key, rsa_public_t &pub);
    bool rsa_encode(uint64_t plain,const rsa_public_t &pub,uint64_t &encoded);
    bool rsa_decode(uint64_t encoded,const rsa_private_t &key,uint64_t &plain);

    bool decode_rsakey(const buffer_t &buffer,std::vector<buffer_t> &fields);
    /*  version           Version,
        modulus           INTEGER,  -- n
        publicExponent    INTEGER,  -- e
        privateExponent   INTEGER,  -- d
        prime1            INTEGER,  -- p
        prime2            INTEGER,  -- q
        exponent1         INTEGER,  -- d mod (p-1)
        exponent2         INTEGER,  -- d mod (q-1)
        coefficient       INTEGER,  -- (inverse of q) mod p */
};

std::ostream & operator<<(std::ostream &out,const crypto::buffer_t &buffer);
std::ostream & operator<<(std::ostream &out,const crypto::block_t &block);

#endif
