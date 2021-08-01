#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <memory>
#include <cstddef>
#include <immintrin.h>
#include <cpuid.h>

using buffer_t = std::vector<uint8_t>;
using block_t = __m128i;

void fail(std::string msg) {
    std::cout << msg;
    exit(1);
}

std::ostream & operator<<(std::ostream &out,const block_t &b) {
    for (size_t i=0; i<sizeof(block_t); i++)
        out << std::setw(2) << std::setfill('0') << std::hex << (int)((uint8_t *)&b)[i] << " ";
    return out;
}

inline block_t aes_assist(block_t temp1,block_t temp2) { 
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

void aes_key_expand(block_t key, block_t *expanded) { 
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

void output_hex(const buffer_t &buffer) {
    for (size_t i=0; i<buffer.size(); i++) {
        if (i%16 == 0)
            std::cout << std::setw(4) << std::setfill(' ') << std::hex << i << ":";
        std::cout << " " << std::setw(2) << std::setfill('0') << std::hex << +buffer[i];
        if (i%16 == 15)
            std::cout << "\n";
    }
    if (buffer.size()%16)
        std::cout << "\n";
}

void aes_encode(const buffer_t &clear,block_t key,buffer_t &cipher) {
    if (clear.size() % sizeof(block_t) != 0)
        fail("clear text is not multiple of block size");
    block_t expanded[20];
    aes_key_expand(key,expanded);

    cipher.resize(clear.size());
    for (size_t i=0; i < clear.size(); i+=sizeof(block_t)) {
        block_t tmp = _mm_loadu_si128((const block_t *)&clear[i]);
        tmp = _mm_xor_si128(tmp,expanded[0]);    
        for (int j=1; j<10; j++)
            tmp = _mm_aesenc_si128(tmp,expanded[j]); 
        tmp = _mm_aesenclast_si128(tmp,expanded[10]);
        _mm_storeu_si128((block_t *)&cipher[i],tmp); 
    }
}

void aes_decode(const buffer_t &cipher,block_t key,buffer_t &clear) {
    if (cipher.size() % sizeof(block_t) != 0)
        fail("cipher text is not multiple of block size");
    block_t expanded[20];
    aes_key_expand(key,expanded);

    clear.resize(cipher.size());
    for (size_t i=0; i < cipher.size(); i+=sizeof(block_t)) {
        block_t tmp = _mm_loadu_si128((const block_t *)&cipher[i]);
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
        _mm_storeu_si128((block_t *)&clear[i],tmp);
    }
}

void read_file(std::string filename,buffer_t &buffer) {
    std::ifstream in(filename,std::ifstream::binary);
    if (!in) 
        fail(std::string("error opening ")+filename+"\n");
    in.seekg(0,std::ios::end);
    buffer.resize(in.tellg());
    in.seekg(0,std::ios::beg);
    in.read(reinterpret_cast<char *>(&buffer[0]),buffer.size());
}

void write_file(std::string filename,const buffer_t &buffer) {
    std::ofstream out(filename,std::ofstream::binary);
    if (!out) 
        fail(std::string("error opening ")+filename+"\n");
    
    out.write(reinterpret_cast<const char *>(&buffer[0]),buffer.size());
}

int main(int argc,char *argv[])
{
    uint32_t a,b,c,d;
    if (!__get_cpuid_max(0,nullptr) || !__get_cpuid(1,&a,&b,&c,&d) || !(c & bit_AES))
        fail("AES instructions not available\n");

    if (argc != 4) 
        fail(std::string("usage: ")+argv[0]+" hexkey infile outfile\n");

    std::string arg1(argv[1]);
    buffer_t key;
    for (size_t i=0; i<arg1.length(); i+=2)
        key.push_back((uint8_t)stoul(arg1.substr(i,2),nullptr,16));
    if (key.size() > sizeof(block_t))
        fail("key too big\n");
    while (key.size() < sizeof(block_t))
        key.push_back(0);

    buffer_t encoded;
    read_file(argv[2],encoded);
    if (encoded.size() % sizeof(block_t) != 0) 
        fail("cipher text not a multiple of block size\n");

    buffer_t plain;
    aes_decode(encoded,*(block_t *)&key[0],plain);

    write_file(argv[3],plain);
}
