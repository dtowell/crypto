#include "crypto.h"

using namespace crypto;

void fail(std::string msg) 
{
    std::cout << msg;
    exit(1);
}

int main(int argc,char *argv[])
{
    uint32_t a,b,c,d;
    if (!__get_cpuid_max(0,nullptr) || !__get_cpuid(1,&a,&b,&c,&d) || !(c & bit_AES))
        fail("AES instructions not available\n");

    if (argc != 5) 
        fail(std::string("usage: ")+argv[0]+" hexkey hexiv infile outfile\n");

    std::string arg1(argv[1]);
    buffer_t key;
    for (size_t i=0; i<arg1.length(); i+=2)
        key.push_back(static_cast<uint8_t>(stoul(arg1.substr(i,2),nullptr,16)));
    if (key.size() > sizeof(block_t))
        fail("key too big\n");
    while (key.size() < sizeof(block_t))
        key.push_back(0);

    std::string arg2(argv[2]);
    buffer_t iv;
    for (size_t i=0; i<arg2.length(); i+=2)
        iv.push_back(static_cast<uint8_t>(stoul(arg2.substr(i,2),nullptr,16)));
    if (iv.size() > sizeof(block_t))
        fail("iv too big\n");
    while (iv.size() < sizeof(block_t))
        iv.push_back(0);

    buffer_t encoded;
    if (!read_file(argv[3],encoded))
        fail(std::string("error reading from ")+argv[3]+"\n");
    if (encoded.size() % sizeof(block_t) != 0) 
        fail("cipher text not a multiple of block size\n");

    buffer_t plain;
    if (!decode_aes_cbc(encoded,*reinterpret_cast<block_t *>(&key[0]),*reinterpret_cast<block_t *>(&iv[0]),plain))
        fail("AES decoding failed\n");

    if (!write_file(argv[4],plain))
        fail(std::string("error writing to ")+argv[4]+"\n");
}
