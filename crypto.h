#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <algorithm>
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
    using uint128_t = unsigned __int128;

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

    bool is_prime(uint64_t x);
    uint64_t next_prime(uint64_t x);
    uint64_t pow_mod(uint64_t x,uint64_t e,uint64_t m);
    uint64_t inv_mod(uint64_t e,uint64_t m);

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

    class NNI {
    public:
        using digit_t = uint64_t;
        using long_t = uint128_t;
        
        NNI() { }
        NNI(digit_t n);
        NNI(const std::string &str);

        void print() const;
        std::string format() const;
        int size() const { return static_cast<int>(digits.size()); }
        digit_t digit(int i) const { 
            return (i>=0 && i<size()) ? digits.at(i) : 0;
        }
        
        NNI & operator<<=(int n);
        NNI & operator>>=(int n);

        friend NNI operator+(const NNI &u,const NNI &v);
        friend NNI operator-(const NNI &u,const NNI &v);
        friend NNI operator*(const NNI &u,const NNI &v);
        friend NNI operator/(const NNI &u,const NNI &v);
        friend NNI operator%(const NNI &u,const NNI &v);
        friend void divide(NNI &q,NNI &r,const NNI &u,const NNI &v);
        friend NNI expmod(const NNI &a,const NNI &e,const NNI &b);
        friend bool operator<(const NNI &u,const NNI &v);
        friend bool operator==(const NNI &u,const NNI &v);

    protected:
        digit_t & operator[](int i) { return digits.at(static_cast<size_t>(i)); }

        void canonicalize();
        int top_zeros();
        static digit_t find_qhat(digit_t un,digit_t un1,digit_t un2,digit_t vn1,digit_t vn2);

        std::vector<digit_t> digits;        
    };

    class VNNI {
    public:
        using digit_t = NNI::digit_t;
        using long_t = NNI::long_t;
        static digit_t woop_base;

    private:
        VNNI(const NNI &n,digit_t w) : nni(n), woop(w) { }
        digit_t compute_woop() const;

        NNI nni;
        digit_t woop;

    public:
        VNNI() : woop(0) { }
        VNNI(digit_t n) : nni(n), woop(n % woop_base) { }
        VNNI(const std::string &str) : nni(str) { woop=compute_woop(); }
        ~VNNI() { verify(); }

        void print() const;
        std::string format() const { return nni.format(); };
        int size() const { return nni.size(); }
        digit_t digit(int i) const { return nni.digit(i); }
        void verify() const;

        VNNI & operator<<=(int n);
        VNNI & operator>>=(int n);

        friend VNNI operator+(const VNNI &u,const VNNI &v);
        friend VNNI operator-(const VNNI &u,const VNNI &v);
        friend VNNI operator*(const VNNI &u,const VNNI &v);
        friend VNNI operator/(const VNNI &u,const VNNI &v);
        friend VNNI operator%(const VNNI &u,const VNNI &v);
        friend void divide(VNNI &q,VNNI &r,const VNNI &u,const VNNI &v);
        friend VNNI expmod(const VNNI &a,const VNNI &e,const VNNI &b);
        friend bool operator<(const VNNI &u,const VNNI &v) { return u.nni<v.nni; }
        friend bool operator==(const VNNI &u,const VNNI &v) { return u.nni==v.nni; }
    };

#if 0
    using digit_t = uint64_t;
    using long_t = uint128_t;
    using nni_t = std::vector<digit_t>;

    void set(nni_t &r, digit_t n);
    void set(nni_t &r, const std::string & str);
    void shiftleft(nni_t &r,size_t n);
    void shiftright(nni_t &r,size_t n);
    void add(nni_t &r,const nni_t &u,const nni_t &v);
    void subtract(nni_t &r,const nni_t &u,const nni_t &v);
    void multiply(nni_t &r,const nni_t &u,const nni_t &v);
    void divide(nni_t &q,nni_t &r,const nni_t &u,const nni_t &v);
    void expmod(nni_t &r,const nni_t &a,const nni_t &e,const nni_t &b);
    bool lesser(const nni_t &u,const nni_t &v);

    digit_t digit(const nni_t &n,size_t i);
    std::string format(const nni_t &u);
    size_t top_zeros(const nni_t &u);
    void canonicalize(const nni_t &u);
#endif

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
//std::ostream & operator<<(std::ostream &out,const crypto::nni_t &n);
std::ostream & operator<<(std::ostream &out,const crypto::NNI &n);

#endif
