#include "crypto.h"

std::ostream & operator<<(std::ostream &out,const crypto::buffer_t &buffer) {
    for (size_t i=0; i<buffer.size(); i++) {
        if (i%16 == 0)
            out << std::setw(4) << std::setfill(' ') << std::hex << i << ":";
        out << " " << std::setw(2) << std::setfill('0') << std::hex << +buffer[i];
        if (i%16 == 15)
            out << "\n";
    }
    if (buffer.size()%16)
        out << "\n";
    return out;
}

std::ostream & operator<<(std::ostream &out,const crypto::block_t &b) {
    for (size_t i=0; i<sizeof(crypto::block_t); i++)
        out << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(*reinterpret_cast<uint8_t *>(&b[i])) << " ";
    return out;
}

std::ostream & operator<<(std::ostream &out,const crypto::nni_t &u) {
    for (auto d:u)
        out << std::hex << std::setw(16) << std::setfill('0') << d << " ";
    return out;
}

namespace crypto {

    bool read_file(std::string filename,buffer_t &buffer) {
        std::ifstream in(filename,std::ifstream::binary);
        if (!in) 
            return false;
        in.seekg(0,std::ios::end);
        buffer.resize(in.tellg());
        in.seekg(0,std::ios::beg);
        in.read(reinterpret_cast<char *>(&buffer[0]),buffer.size());
        return true;
    }

    bool write_file(std::string filename,const buffer_t &buffer) {
        std::ofstream out(filename,std::ofstream::binary);
        if (!out) 
            return false;
        
        out.write(reinterpret_cast<const char *>(&buffer[0]),buffer.size());
        return true;
    }

    void encode_base64(const buffer_t &plain,std::string &encoded) {
        static const char * base64 = 
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789+/";

        encoded.clear();
        for (size_t i=0; i<plain.size(); i+=3) {
            if (i && i % 57 == 0)
                encoded += '\n';

            encoded += base64[plain[i] >> 2];

            if (i+1 < plain.size()) {
                encoded += base64[((plain[i] & 0x03) << 4) + (plain[i+1] >> 4)];

                if (i+2 < plain.size()) {
                    encoded += base64[((plain[i+1] & 0x0f) << 2) + ((plain[i+2] & 0xc0) >> 6)];
                    encoded += base64[  plain[i+2] & 0x3f];
                }
                else {
                    encoded += base64[(plain[i+1] & 0x0f) << 2];
                    encoded += '=';
                }
            }
            else {
                encoded += base64[(plain[i] & 0x03) << 4];
                encoded += '=';
                encoded += '=';
            }
        }
        encoded += '\n';
    }

    void decode_base64(const std::string &encoded,buffer_t &buffer) {

        // TODO this should probably support/ignore newlines since we generate them in encode_base64()

        static const int base64[256] =
        {
            0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
            0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
            0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  62, 63, 62, 62, 63,
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0,  0,  0,  0,  0,  0,
            0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0,  0,  0,  0,  63,
            0,  26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
        };

        size_t size = encoded.size();
        size_t pad1 = size % 4 || encoded[size-1] == '=';
        size_t pad2 = pad1 && (size % 4 > 2 || encoded[size-2] != '=');
        const size_t last = (encoded.size()-pad1)/4 << 2;

        buffer.resize(0);
        for (size_t i=0; i<last; i+=4) {
            uint32_t n = base64[static_cast<uint8_t>(encoded[i])] << 18 
                | base64[static_cast<uint8_t>(encoded[i+1])] << 12 
                | base64[static_cast<uint8_t>(encoded[i+2])] << 6 
                | base64[static_cast<uint8_t>(encoded[i+3])];
            buffer.push_back(static_cast<uint8_t>(n >> 16));
            buffer.push_back(static_cast<uint8_t>(n >> 8 & 0xFF));
            buffer.push_back(static_cast<uint8_t>(n & 0xFF));
        }
        if (pad1) {
            uint32_t n = base64[static_cast<uint8_t>(encoded[last])] << 18 | base64[static_cast<uint8_t>(encoded[last+1])] << 12;
            buffer.push_back(static_cast<uint8_t>(n >> 16));
            if (pad2) {
                n |= base64[static_cast<uint8_t>(encoded[last+2])] << 6;
                buffer.push_back(static_cast<uint8_t>(n >> 8 & 0xFF));
            }
        }
    }

    static inline block_t aes_assist(block_t temp1,block_t temp2) { 
        temp2 = _mm_shuffle_epi32(temp2,0xff); 
        block_t temp3 = _mm_slli_si128(temp1,0x4); 
        temp1 = _mm_xor_si128(temp1,temp3); 
        temp3 = _mm_slli_si128(temp3,0x4); 
        temp1 = _mm_xor_si128(temp1,temp3); 
        temp3 = _mm_slli_si128(temp3,0x4); 
        temp1 = _mm_xor_si128(temp1,temp3);   
        temp1 = _mm_xor_si128(temp1,temp2); 
        return temp1; 
    } 

    using expanded_key_t = block_t[20];

    static void aes_key_expand(block_t key, expanded_key_t expanded) { 
        block_t temp1,temp2; 
        
        temp1 = _mm_loadu_si128(&key); 
        expanded[0] = temp1; 
        temp2 = _mm_aeskeygenassist_si128(temp1,0x1); 
        temp1 = aes_assist(temp1,temp2); 
        expanded[1] = temp1; 
        temp2 = _mm_aeskeygenassist_si128(temp1,0x2); 
        temp1 = aes_assist(temp1,temp2); 
        expanded[2] = temp1;   
        temp2 = _mm_aeskeygenassist_si128(temp1,0x4); 
        temp1 = aes_assist(temp1,temp2); 
        expanded[3] = temp1; 
        temp2 = _mm_aeskeygenassist_si128(temp1,0x8); 
        temp1 = aes_assist(temp1,temp2); 
        expanded[4] = temp1; 
        temp2 = _mm_aeskeygenassist_si128(temp1,0x10); 
        temp1 = aes_assist(temp1,temp2); 
        expanded[5] = temp1; 
        temp2 = _mm_aeskeygenassist_si128(temp1,0x20); 
        temp1 = aes_assist(temp1,temp2); 
        expanded[6] = temp1; 
        temp2 = _mm_aeskeygenassist_si128(temp1,0x40); 
        temp1 = aes_assist(temp1,temp2); 
        expanded[7] = temp1; 
        temp2 = _mm_aeskeygenassist_si128(temp1,0x80); 
        temp1 = aes_assist(temp1,temp2); 
        expanded[8] = temp1;     
        temp2 = _mm_aeskeygenassist_si128(temp1,0x1b); 
        temp1 = aes_assist(temp1,temp2); 
        expanded[9] = temp1; 
        temp2 = _mm_aeskeygenassist_si128(temp1,0x36); 
        temp1 = aes_assist(temp1,temp2); 
        expanded[10] = temp1;
        expanded[11] = _mm_aesimc_si128(expanded[9]);
        expanded[12] = _mm_aesimc_si128(expanded[8]);
        expanded[13] = _mm_aesimc_si128(expanded[7]);
        expanded[14] = _mm_aesimc_si128(expanded[6]);
        expanded[15] = _mm_aesimc_si128(expanded[5]);
        expanded[16] = _mm_aesimc_si128(expanded[4]);
        expanded[17] = _mm_aesimc_si128(expanded[3]);
        expanded[18] = _mm_aesimc_si128(expanded[2]);
        expanded[19] = _mm_aesimc_si128(expanded[1]);
    } 

    bool encode_aes_ecb(const buffer_t &clear,block_t key,buffer_t &cipher) {
        if (clear.size() % sizeof(block_t) != 0)
            return false;
        expanded_key_t expanded;
        aes_key_expand(key,expanded);

        cipher.resize(clear.size());
        for (size_t i=0; i < clear.size(); i+=sizeof(block_t)) {
            block_t tmp = _mm_loadu_si128(reinterpret_cast<const block_t *>(&clear[i]));
            tmp = _mm_xor_si128(tmp,expanded[0]);    
            for (int j=1; j<10; j++)
                tmp = _mm_aesenc_si128(tmp,expanded[j]); 
            tmp = _mm_aesenclast_si128(tmp,expanded[10]);
            _mm_storeu_si128(reinterpret_cast<block_t *>(&cipher[i]),tmp); 
        }
        return true;
    }

    bool encode_aes_cbc(const buffer_t &clear,block_t key,block_t iv,buffer_t &cipher) {
        buffer_t padded(clear);
        size_t padding = sizeof(block_t) - cipher.size() % sizeof(block_t);
        for (size_t i=0; i<padding; ++i)
            padded.push_back(static_cast<uint8_t>(padding));

        expanded_key_t expanded;
        aes_key_expand(key,expanded);

        cipher.resize(padded.size());
        block_t tmp = iv;
        for (size_t i=0; i < padded.size(); i+=sizeof(block_t)) {
            tmp = _mm_xor_si128(tmp,*reinterpret_cast<const block_t *>(&padded[i]));
            tmp = _mm_xor_si128(tmp,expanded[0]);    
            for (int j=1; j<10; j++)
                tmp = _mm_aesenc_si128(tmp,expanded[j]); 
            tmp = _mm_aesenclast_si128(tmp,expanded[10]);
            _mm_storeu_si128(reinterpret_cast<block_t *>(&cipher[i]),tmp); 
        }
        return true;
    }

    bool decode_aes_ecb(const buffer_t &cipher,block_t key,buffer_t &clear) {
        if (cipher.size() % sizeof(block_t) != 0)
            return false;
        expanded_key_t expanded;
        aes_key_expand(key,expanded);

        clear.resize(cipher.size());
        for (size_t i=0; i < cipher.size(); i+=sizeof(block_t)) {
            block_t tmp = _mm_loadu_si128(reinterpret_cast<const block_t *>(&cipher[i]));
            tmp = _mm_xor_si128(tmp,expanded[10]);
            tmp = _mm_aesdec_si128(tmp,expanded[11]);
            tmp = _mm_aesdec_si128(tmp,expanded[12]);
            tmp = _mm_aesdec_si128(tmp,expanded[13]);
            tmp = _mm_aesdec_si128(tmp,expanded[14]);
            tmp = _mm_aesdec_si128(tmp,expanded[15]);
            tmp = _mm_aesdec_si128(tmp,expanded[16]);
            tmp = _mm_aesdec_si128(tmp,expanded[17]);
            tmp = _mm_aesdec_si128(tmp,expanded[18]);
            tmp = _mm_aesdec_si128(tmp,expanded[19]);
            tmp = _mm_aesdeclast_si128(tmp,expanded[0]);
            _mm_storeu_si128(reinterpret_cast<block_t *>(&clear[i]),tmp);
        }
        return true;
    }

    bool decode_aes_cbc(const buffer_t &cipher,block_t key,block_t iv,buffer_t &clear) {
        if (cipher.size() % sizeof(block_t) != 0)
            return false;
        expanded_key_t expanded;
        aes_key_expand(key,expanded);

        clear.resize(cipher.size());
        block_t prev = iv;
        for (size_t i=0; i < cipher.size(); i+=sizeof(block_t)) {
            block_t tmp = _mm_loadu_si128(reinterpret_cast<const block_t *>(&cipher[i]));
            block_t save = tmp;
            tmp = _mm_xor_si128(tmp,expanded[10]);
            tmp = _mm_aesdec_si128(tmp,expanded[11]);
            tmp = _mm_aesdec_si128(tmp,expanded[12]);
            tmp = _mm_aesdec_si128(tmp,expanded[13]);
            tmp = _mm_aesdec_si128(tmp,expanded[14]);
            tmp = _mm_aesdec_si128(tmp,expanded[15]);
            tmp = _mm_aesdec_si128(tmp,expanded[16]);
            tmp = _mm_aesdec_si128(tmp,expanded[17]);
            tmp = _mm_aesdec_si128(tmp,expanded[18]);
            tmp = _mm_aesdec_si128(tmp,expanded[19]);
            tmp = _mm_aesdeclast_si128(tmp,expanded[0]);
            tmp = _mm_xor_si128(tmp,prev);
            _mm_storeu_si128(reinterpret_cast<block_t *>(&clear[i]),tmp);
            prev = save;
        }

        // count final identical bytes
        size_t same = 0;
        while (same<clear.size() && clear[clear.size()-same-1]==clear.back())
            ++same;
        
        // validate
        if (same < clear.back())
            return false;
    
        // remove padding
        for (same=clear.back(); same; --same)
            clear.pop_back();

        return true;
    }

    uint32_t rotate(uint32_t x,uint8_t n) {
        return x>>n | x<<(32-n);
    }

    bool hash_sha256(const buffer_t &clear,buffer_t &hash) {
        uint32_t h0 = 0x6a09e667u;
        uint32_t h1 = 0xbb67ae85u;
        uint32_t h2 = 0x3c6ef372u;
        uint32_t h3 = 0xa54ff53au;
        uint32_t h4 = 0x510e527fu;
        uint32_t h5 = 0x9b05688cu;
        uint32_t h6 = 0x1f83d9abu;
        uint32_t h7 = 0x5be0cd19u;

        static uint32_t k[] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2        
        };

        // pad message
        buffer_t padded(clear);
        uint64_t size = clear.size();
        size_t padding = 64 - (size+1+8)%64;
        padded.push_back(0x80);
        while (padding--)
            padded.push_back(0);
        for (size_t i=0; i<8; i++)
            padded.push_back(static_cast<uint8_t>((size*8)>>(56-i*8)));
        assert(padded.size()%64 == 0);

        // process each 64-byte / 512-bit chunk
        uint32_t *message = reinterpret_cast<uint32_t *>(&padded[0]);
        for (size_t index=0; index<padded.size(); index+=64) {
            uint32_t w[64];
            for (size_t i=0; i<16; ++i)
                w[i] = __builtin_bswap32(*message++);
            for (size_t i=16; i<64; ++i) {
                uint32_t s0 = rotate(w[i-15], 7) ^ rotate(w[i-15],18) ^ (w[i-15] >>  3);
                uint32_t s1 = rotate(w[i- 2],17) ^ rotate(w[i- 2],19) ^ (w[i- 2] >> 10);
                w[i] = w[i-16] + s0 + w[i-7] + s1;
            }

            uint32_t a = h0;
            uint32_t b = h1;
            uint32_t c = h2;
            uint32_t d = h3;
            uint32_t e = h4;
            uint32_t f = h5;
            uint32_t g = h6;
            uint32_t h = h7;

            //std::cout << a << " ";
            //std::cout << b << " ";
            //std::cout << c << " ";
            //std::cout << d << " ";
            //std::cout << e << " ";
            //std::cout << f << " ";
            //std::cout << g << " ";
            //std::cout << h << "\n\n";

            for (size_t i=0; i<64; ++i) {
                uint32_t S1 = rotate(e,6) ^ rotate(e,11) ^ rotate(e,25);
                uint32_t ch = (e & f) ^ (~e & g);
                uint32_t temp1 = h + S1 + ch + k[i] + w[i];
                uint32_t S0 = rotate(a,2) ^ rotate(a,13) ^ rotate(a,22);
                uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                uint32_t temp2 = S0 + maj;
        
                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;

                //std::cout << a << " ";
                //std::cout << b << " ";
                //std::cout << c << " ";
                //std::cout << d << " ";
                //std::cout << e << " ";
                //std::cout << f << " ";
                //std::cout << g << " ";
                //std::cout << h << "\n";
            }

            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
            h5 += f;
            h6 += g;
            h7 += h;
        }

        // big-endian
        hash.resize(32);
        uint32_t * h = reinterpret_cast<uint32_t *>(&hash[0]);
        h[0] = __builtin_bswap32(h0);
        h[1] = __builtin_bswap32(h1);
        h[2] = __builtin_bswap32(h2);
        h[3] = __builtin_bswap32(h3);
        h[4] = __builtin_bswap32(h4);
        h[5] = __builtin_bswap32(h5);
        h[6] = __builtin_bswap32(h6);
        h[7] = __builtin_bswap32(h7);
        
        return true;
    }

    uint64_t rotate(uint64_t x,uint8_t n) {
        return x>>n | x<<(64-n);
    }

    bool hash_sha512(const buffer_t &clear,buffer_t &hash,uint64_t *ha) {

        static uint64_t k[] = {
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
            0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
            0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
            0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
            0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
            0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
            0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
            0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
            0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
            0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
            0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
            0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
            0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        };

        // pad message
        buffer_t padded(clear);
        uint64_t size = clear.size();
        size_t padding = 128 - (size+1+16)%128 + 8;
        padded.push_back(0x80);
        while (padding--)
            padded.push_back(0);
        for (size_t i=0; i<8; i++)
            padded.push_back(static_cast<uint8_t>((size*8)>>(56-i*8)));
        assert(padded.size()%128 == 0);

        // process each 128-byte / 1024-bit chunk
        uint64_t *message = reinterpret_cast<uint64_t *>(&padded[0]);
        for (size_t index=0; index<padded.size(); index+=128) {
            uint64_t w[80];
            for (size_t i=0; i<16; ++i)
                w[i] = __builtin_bswap64(*message++);
            for (size_t i=16; i<80; ++i) {
                uint64_t s0 = rotate(w[i-15], 1) ^ rotate(w[i-15], 8) ^ (w[i-15] >> 7);
                uint64_t s1 = rotate(w[i- 2],19) ^ rotate(w[i- 2],61) ^ (w[i- 2] >> 6);
                w[i] = w[i-16] + s0 + w[i-7] + s1;
            }

            uint64_t a = ha[0];
            uint64_t b = ha[1];
            uint64_t c = ha[2];
            uint64_t d = ha[3];
            uint64_t e = ha[4];
            uint64_t f = ha[5];
            uint64_t g = ha[6];
            uint64_t h = ha[7];

            for (size_t i=0; i<80; ++i) {
                uint64_t S1 = rotate(e,14) ^ rotate(e,18) ^ rotate(e,41);
                uint64_t ch = (e & f) ^ (~e & g);
                uint64_t temp1 = h + S1 + ch + k[i] + w[i];
                uint64_t S0 = rotate(a,28) ^ rotate(a,34) ^ rotate(a,39);
                uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
                uint64_t temp2 = S0 + maj;
        
                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;

                //std::cout << a << " ";
                //std::cout << b << " ";
                //std::cout << c << " ";
                //std::cout << d << " ";
                //std::cout << e << " ";
                //std::cout << f << " ";
                //std::cout << g << " ";
                //std::cout << h << "\n";
            }

            ha[0] += a;
            ha[1] += b;
            ha[2] += c;
            ha[3] += d;
            ha[4] += e;
            ha[5] += f;
            ha[6] += g;
            ha[7] += h;
        }

        // big-endian
        hash.resize(64);
        uint64_t * h = reinterpret_cast<uint64_t *>(&hash[0]);
        h[0] = __builtin_bswap64(ha[0]);
        h[1] = __builtin_bswap64(ha[1]);
        h[2] = __builtin_bswap64(ha[2]);
        h[3] = __builtin_bswap64(ha[3]);
        h[4] = __builtin_bswap64(ha[4]);
        h[5] = __builtin_bswap64(ha[5]);
        h[6] = __builtin_bswap64(ha[6]);
        h[7] = __builtin_bswap64(ha[7]);
        
        return true;
    }


    bool hash_sha512(const buffer_t &clear,buffer_t &hash) {
        uint64_t h[] = {
            0x6a09e667f3bcc908ull,
            0xbb67ae8584caa73bull,
            0x3c6ef372fe94f82bull,
            0xa54ff53a5f1d36f1ull,
            0x510e527fade682d1ull,
            0x9b05688c2b3e6c1full,
            0x1f83d9abfb41bd6bull,
            0x5be0cd19137e2179ull,
        };
        return hash_sha512(clear,hash,h);
    }

    bool hash_sha512_256(const buffer_t &clear,buffer_t &hash)
    {
        // bootstrap
        uint64_t h[] = {
            0x6a09e667f3bcc908ull ^ 0xa5a5a5a5a5a5a5a5,
            0xbb67ae8584caa73bull ^ 0xa5a5a5a5a5a5a5a5,
            0x3c6ef372fe94f82bull ^ 0xa5a5a5a5a5a5a5a5,
            0xa54ff53a5f1d36f1ull ^ 0xa5a5a5a5a5a5a5a5,
            0x510e527fade682d1ull ^ 0xa5a5a5a5a5a5a5a5,
            0x9b05688c2b3e6c1full ^ 0xa5a5a5a5a5a5a5a5,
            0x1f83d9abfb41bd6bull ^ 0xa5a5a5a5a5a5a5a5,
            0x5be0cd19137e2179ull ^ 0xa5a5a5a5a5a5a5a5,
        };
        buffer_t name{'S','H','A','-','5','1','2','/','2','5','6'};
        buffer_t temp;
        if (!hash_sha512(name,temp,h))
            return false;
        
        // full hash with inital h0 thru h7
        for (size_t i=0; i<8; i++)
            h[i] = __builtin_bswap64(reinterpret_cast<uint64_t *>(&temp[0])[i]);
        if (!hash_sha512(clear,temp,h))
            return false;

        //std::cout << std::hex << h[0] << " ";
        //std::cout << h[1] << " ";
        //std::cout << h[2] << " ";
        //std::cout << h[3] << " ";
        //std::cout << h[4] << " ";
        //std::cout << h[5] << " ";
        //std::cout << h[6] << " ";
        //std::cout << h[7] << "\n";

        hash.resize(256/8);
        for (size_t i=0; i<256/8; i++)
            hash[i] = temp[i];
        return true;
    }

    bool rand_rdrand(size_t bytes,buffer_t &buffer)
    {
        uint32_t a,b,c,d;
        if (!__get_cpuid_max(0,nullptr) || !__get_cpuid(0,&a,&b,&c,&d) || !(c & bit_RDRND))
            return false;
        buffer.resize((bytes+3)&~3); // round up to multiple of 4
        for (size_t i=0; i<bytes; i+=4)
            if (!_rdrand32_step(reinterpret_cast<uint32_t *>(&buffer[i])))
                return false;
        return true;
    }

    bool is_prime(uint64_t x)
    {
        if (x==2 || x==3)
            return true;
        if (x<=1 || x%2==0 || x%3==0)
            return false;
        for (uint64_t n=5; n*n<=x; n+=6)
            if (x%n==0 || x%(n+2)==0)
                return false;
        return true;
    }

    uint64_t next_prime(uint64_t x)
    {
        while (!is_prime(++x))
            ;
        return x;
    }

    uint64_t pow_mod(uint64_t base,uint64_t exp,uint64_t mod)
    {
        uint64_t r = 1;
        base %= mod;
        while (exp) {
            // if (trace) std::cout << base << " " << exp << " " << mod << " " << r << "\n";
            if (exp&1)
                r = static_cast<uint64_t>(static_cast<uint128_t>(r)*base % mod);
            exp >>= 1;
            base = static_cast<uint64_t>(static_cast<uint128_t>(base)*base % mod);
        }
        return r;
    }

    uint64_t inv_mod(uint64_t e,uint64_t m)
    {
        // https://crypto.stackexchange.com/questions/5889/calculating-rsa-private-exponent-when-given-public-exponent-and-the-modulus-fact
        uint64_t a = e;
        uint64_t b = m;
        uint64_t x = 0;
        uint64_t y = 1;
        while (true) {
            if (a==1)
                return y;
            assert(a != 0);
            x = static_cast<uint64_t>(x + static_cast<uint128_t>(b/a)*y);
            b %= a;
            if (b==1) return m-x;
            //if (b==0) {
            //    std::cout << a << "\n";
            //    std::cout << x << "\n";
            //    std::cout << y << "\n";
            //}
            assert(b != 0);
            y = static_cast<uint64_t>(y + static_cast<uint128_t>(a/b)*x);
            a %= b;
        }
    }

    bool rsa_generate(rsa_private_t &key) 
    {
        // https://www.di-mgt.com.au/rsa_alg.html
        key.e = 65537;
        key.p = 1;
        while (key.p % key.e == 1) {
            buffer_t bytes;
            if (!rand_rdrand(4,bytes))
                return false;
            bytes[3] |= 3<<6;
            key.p = next_prime(*reinterpret_cast<uint32_t *>(&bytes[0]));
        }
        key.q = 1;
        while (key.q % key.e == 1) {
            buffer_t bytes;
            if (!rand_rdrand(4,bytes))
                return false;
            bytes[3] |= 3<<6;
            key.q = next_prime(*reinterpret_cast<uint32_t *>(&bytes[0]));
        }

        key.d = inv_mod(key.e,(key.p-1)*(key.q-1));
        return true;
    }

    bool rsa_publish(const rsa_private_t &key, rsa_public_t &pub)
    {
        pub.n = key.p * key.q;
        pub.e = key.e;
        return true;
    }

    bool rsa_encode(uint64_t plain,const rsa_public_t &pub,uint64_t &encoded)
    {
        encoded = pow_mod(plain,pub.e,pub.n);
        return true;
    }
    bool rsa_decode(uint64_t encoded,const rsa_private_t &key,uint64_t &plain)
    {
        plain = pow_mod(encoded,key.d,key.p*key.q);
        return true;
    }


    void set(nni_t &r, digit_t n) {
        r.clear();
        if (n)
            r.push_back(n);
    }

    void set(nni_t &r, const std::string & str) {
        r.clear();
        nni_t ten,digit,t;
        set(ten,10);
        for (char c:str) {
            set(digit,c-'0');
            multiply(t,ten,r);
            add(r,t,digit);
        }
    }

    void canonicalize(nni_t &u) {
        while (u.size() && u.back()==0)
            u.pop_back();
    }

    void shiftleft(nni_t &u,size_t shift) {
        assert(shift < sizeof(digit_t)*8);
        if (shift == 0) return;

        digit_t bits = 0;
        for (size_t i=0; i<u.size(); i++) {
            digit_t d = u[i];
            u[i] = (d<<shift) + bits;
            bits = d>>(sizeof(digit_t)*8-shift);
        }
        if (bits > 0)
            u.push_back(bits);
    }

    void shiftright(nni_t &u,size_t shift) {
        assert(shift < sizeof(digit_t)*8);
        if (shift == 0) return;

        digit_t bits = 0;
        for (size_t i=u.size(); i-->0; ) {
            digit_t d = u[i];
            u[i] = (d>>shift) + bits;
            bits = d<<(sizeof(digit_t)*8-shift);
        }
        canonicalize(u);
    }

    size_t top_zeros(const nni_t &u) {
        const digit_t HALF = 1UL<<(sizeof(digit_t)*8-1);
        digit_t x = u.back();
        int shift = 0;
        while (x < HALF) {
            x <<= 1;
            shift++;
        }
        return shift;
    }

    digit_t digit(const nni_t &n,size_t i) { 
        return i<n.size() ? n[i] : 0; 
    }

    std::string format(const nni_t &u) {
        if (u.size() == 0)
            return "0";
        
        nni_t ten;
        set(ten,10);
        std::string digits;
        nni_t t(u);
        while (t.size() > 0) {
            nni_t q,r;
            divide(q,r,t,ten);
            t = q;
            //std::cout << "t=" << t << "\n";
            //std::cout << "ten=" << ten << "\n";
            //std::cout << "q=" << q << "\n";
            //std::cout << "r=" << r << "\n";
            assert(r.size() < 2);
            if (r.size())
                digits = std::string(1,static_cast<char>(r[0]+'0')) + digits;
            else 
                digits = "0" + digits;
        }
        return digits;
    }

    void add(nni_t &r,const nni_t &u,const nni_t &v) {
        size_t m = std::max(u.size(),v.size());
        r.clear();
        digit_t carry = 0;
        for (size_t i=0; i<m; i++) {
            digit_t c = digit(u,i) + digit(v,i) + carry;
            if (carry)
                carry = c <= digit(u,i);
            else
                carry = c < digit(v,i);
            r.push_back(c);
        }
        if (carry)
            r.push_back(1);
    }

    bool lesser(const nni_t &u,const nni_t &v) {
        if (u.size() < v.size())
            return true;
            
        if (u.size() > v.size())
            return false;
            
        for (size_t i=u.size(); i-->0; ) {
            if (u[i] < v[i])
                return true;
            if (u[i] > v[i])
                return false;
        }
        return false;
    }

    void subtract(nni_t &r,const nni_t &u,const nni_t &v) {
        assert(!lesser(u,v));

        size_t size = std::max(u.size(),v.size());
        r.clear();
        digit_t borrow = false;
        for (size_t i=0; i<size; i++) {
            r.push_back(digit(u,i)-digit(v,i)-borrow);
            if (borrow)
                borrow = digit(u,i) <= digit(v,i);
            else
                borrow = digit(u,i) < digit(v,i);
        }
        canonicalize(r);
    }

    void multiply(nni_t &r,const nni_t &u,const nni_t &v) {
        r.resize(u.size()+v.size());
        std::fill(r.begin(),r.end(),0);

        for (size_t j=0; j<v.size(); j++) {
            long_t z = 0;
            for (size_t i=0; i<u.size() || z>0; i++) {
                z += r[j+i];
                z += static_cast<long_t>(digit(u,i)) * v[j];
                r[j+i] = static_cast<digit_t>(z);
                z >>= sizeof(digit_t)*8;
            }
        }
        canonicalize(r);
    }

    digit_t find_qhat(digit_t un,digit_t un1,digit_t un2,digit_t vn1,digit_t vn2)
    {
        const int shift = sizeof(digit_t)*8;
        long_t q = ((static_cast<long_t>(un)<<shift) + un1) / vn1;
        long_t r = ((static_cast<long_t>(un)<<shift) + un1) % vn1;
        if (q>>shift) {
            q--;
            r += vn1;
        }
        int x=0;
        while ((r>>shift)==0 && q*vn2 > (r<<shift)+un2) {
            q--;
            r += vn1;
            x++;
        }
        assert(x < 3);
        return static_cast<digit_t>(q);        
    }

    void divide(nni_t &q,nni_t &r,const nni_t &u,const nni_t &v) {
        assert(v.size() > 0);

        if (lesser(u,v)) {
            q.clear(); // q = 0
            r = u;
            return;
        }
        
        if (v.size()==1 && u.size()==1) {
            set(q,u[0] / v[0]);
            set(r,u[0] % v[0]);
            return;
        }

        if (v.size()==1 && u.size()==2) {
            long_t n = (static_cast<long_t>(u[1])<<(sizeof(digit_t)*8)) + u[0];
            long_t a = n / v[0];
            set(q,static_cast<digit_t>(a));
            digit_t h = static_cast<digit_t>(a >> (sizeof(digit_t)*8));
            if (h)
                q.push_back(h);
            set(r,static_cast<digit_t>(n % v[0]));
            return;
        }

        nni_t v2(v);
        size_t shift = top_zeros(v2);
        shiftleft(v2,shift);
        r = u;
        shiftleft(r,shift);
        
        int m = static_cast<int>(r.size());
        int n = static_cast<int>(v2.size());
        q.resize(m-n+1);
        for (int k = m-n; k>=0; k--) {
            digit_t qhat = find_qhat(digit(r,k+n),digit(r,k+n-1),k+n-2<0?0:digit(r,k+n-2),digit(v2,n-1),n-2<0?0:digit(v2,n-2));
            nni_t t;
            t.resize(k+1);
            t[k] = qhat;
            for (int i=0; i<k; i++)
                t[i]=0;
                
            nni_t w;
            multiply(w,v2,t); // w = q*v
            if (lesser(r,w)) {
                t[k] = --qhat;
                multiply(w,v2,t);
            }
            subtract(t,r,w); // t = u-q*v
            q[k] = qhat;
            
            r = t;
        }
        shiftright(r,shift);
        canonicalize(r);
        canonicalize(q);
    }

    void expmod(nni_t &r,const nni_t &a,const nni_t &e,const nni_t &b) {
        nni_t a2(a);
        nni_t t,t2;
        set(r,1);
        int shift = sizeof(digit_t)*8;
        for (size_t i=0; i<e.size()*shift; i++) {
            if (e[i/shift] & (1UL<<(i%shift))) {
                multiply(t,r,a2);
                divide(t2,r,t,b);
            }
            multiply(t,a2,a2);
            divide(t2,a2,t,b);
        }
    }

    bool decode_rsakey(const buffer_t &buffer,std::vector<buffer_t> &fields) 
    {
        fields.resize(0);
        size_t i=0;
        if (buffer[i++] != 0x30) return false;
        if (buffer[i++] != 0x82) return false;
        size_t s = buffer[i]<<8 | buffer[i+1];
        if (s != buffer.size()-4) return false;
        i+=2;

        for (int j=0; j<9; j++) {
            if (buffer[i++] != 0x02) return false;
            size_t len = buffer[i++];
            if (len >= 0x80) {
                if (len != 0x82) return false;
                len = buffer[i]<<8 | buffer[i+1];
                i+=2;
            }
            std::vector<uint8_t> t(len);
            for (size_t k=0; k<len; k++)
                t[k] = buffer[i++];
            fields.push_back(t);
        }
        return true;
    }

};
