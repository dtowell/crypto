#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <string>
#include <memory>
#include <cstddef>
#include <immintrin.h>
#include <cassert>

#ifndef _CRYPTO_H
#define _CRYPTO_H

namespace crypto {
    using buffer_t = std::vector<uint8_t>;
    using block_t = __m128i;

    bool read_file(std::string filename,buffer_t &buffer);
    bool write_file(std::string filename,const buffer_t &buffer);

    void encode_base64(const buffer_t &plain,std::string &encoded);
    void decode_base64(const std::string &encoded,buffer_t &buffer);

    bool encode_aes_ecb(const buffer_t &clear,block_t key,buffer_t &cipher);
    bool decode_aes_ecb(const buffer_t &cipher,block_t key,buffer_t &clear);

    bool encode_aes_cbc(const buffer_t &clear,block_t key,block_t iv,buffer_t &cipher);
    bool decode_aes_cbc(const buffer_t &cipher,block_t key,block_t iv,buffer_t &clear);

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
