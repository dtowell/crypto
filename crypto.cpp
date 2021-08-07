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

    bool decode_rsakey(const buffer_t &buffer,std::vector<buffer_t> &fields) {
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
