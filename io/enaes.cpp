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
using v128_t = __m128i;

void fail(std::string msg) {
    std::cout << msg;
    exit(1);
}

inline __m128i aes_assest(v128_t temp1, v128_t temp2) { 
    temp2 = _mm_shuffle_epi32 (temp2 ,0xff); 
    v128_t temp3 = _mm_slli_si128 (temp1, 0x4); 
    temp1 = _mm_xor_si128 (temp1, temp3); 
    temp3 = _mm_slli_si128 (temp3, 0x4); 
    temp1 = _mm_xor_si128 (temp1, temp3); 
    temp3 = _mm_slli_si128 (temp3, 0x4); 
    temp1 = _mm_xor_si128 (temp1, temp3);   
    temp1 = _mm_xor_si128 (temp1, temp2); 
    return temp1; 
} 
 
void aes_key_expand(const unsigned char *userkey, unsigned char *key) { 
    v128_t temp1, temp2; 
    v128_t *Key_Schedule = (v128_t*)key; 
     
    temp1 = _mm_loadu_si128((v128_t*)userkey); 
    Key_Schedule[0] = temp1; 
    temp2 = _mm_aeskeygenassist_si128 (temp1 ,0x1); 
    temp1 = aes_assest(temp1, temp2); 
    Key_Schedule[1] = temp1; 
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x2); 
    temp1 = aes_assest(temp1, temp2); 
    Key_Schedule[2] = temp1;   
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x4); 
    temp1 = aes_assest(temp1, temp2); 
    Key_Schedule[3] = temp1; 
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x8); 
    temp1 = aes_assest(temp1, temp2); 
    Key_Schedule[4] = temp1; 
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x10); 
    temp1 = aes_assest(temp1, temp2); 
    Key_Schedule[5] = temp1; 
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x20); 
    temp1 = aes_assest(temp1, temp2); 
    Key_Schedule[6] = temp1; 
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x40); 
    temp1 = aes_assest(temp1, temp2); 
    Key_Schedule[7] = temp1; 
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x80); 
    temp1 = aes_assest(temp1, temp2); 
    Key_Schedule[8] = temp1;     
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x1b); 
    temp1 = aes_assest(temp1, temp2); 
    Key_Schedule[9] = temp1; 
    temp2 = _mm_aeskeygenassist_si128 (temp1,0x36); 
    temp1 = aes_assest(temp1, temp2); 
    Key_Schedule[10] = temp1; 
} 
 
void aes_encode(const unsigned char *in,  //pointer to the PLAINTEXT 
                     unsigned char *out,       //pointer to the CIPHERTEXT buffer 
                     unsigned long length,     //text length in bytes 
                     const char *key) {
    if(length%16) 
        length = length/16+1; 
    else 
        length = length/16; 
 
    for (size_t i=0; i < length; i++){ 
        v128_t tmp = _mm_loadu_si128 (&((v128_t*)in)[i]); 
        tmp = _mm_xor_si128 (tmp,((v128_t*)key)[0]);    
        for (int j=1; j<10; j++)
            tmp = _mm_aesenc_si128 (tmp,((v128_t*)key)[j]); 
        tmp = _mm_aesenclast_si128 (tmp,((v128_t*)key)[10]); 
        _mm_storeu_si128 (&((v128_t*)out)[i],tmp); 
    } 
} 
 
void aes_decode(const unsigned char *in,  //pointer to the CIPHERTEXT 
                unsigned char *out,       //pointer to the DECRYPTED TEXT buffer 
                unsigned long length,     //text length in bytes 
                const char *key) {
    if (length%16) 
        length = length/16+1; 
    else 
        length = length/16; 
 
    for (size_t i=0; i < length; i++) { 
        v128_t tmp = _mm_loadu_si128 (&((v128_t*)in)[i]); 
        tmp = _mm_xor_si128 (tmp,((v128_t*)key)[0]);    
        for(int j=1; j <10; j++)
            tmp = _mm_aesdec_si128 (tmp,((v128_t*)key)[j]); 
        tmp = _mm_aesdeclast_si128 (tmp,((v128_t*)key)[10]); 
        _mm_storeu_si128 (&((v128_t*)out)[i],tmp); 
    } 
} 

int main(int argc,char *argv[])
{
    if (argc != 2) 
        fail(std::string("usage: ")+argv[0]+" infile\n");

    uint32_t a,b,c,d;
    if (!__get_cpuid_max(0,nullptr) || !__get_cpuid(0,&a,&b,&c,&d) || !(c & bit_AES))
        fail("AES instructions not available\n");

    std::ifstream in(argv[1]);
    if (!in)
        fail(std::string("error opening ")+argv[1]+"\n");
    std::string input;
    std::string line;
    while (std::getline(in,line))
        input += line;

    buffer_t buffer;
    // decode_base64(input,buffer);

    std::vector<buffer_t> fields;
    // decode_rsakey(buffer,fields);
}
