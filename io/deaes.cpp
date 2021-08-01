#include "crypto.h"

using namespace crypto;

int main(int argc,char *argv[])
{
    uint32_t a,b,c,d;
    if (!__get_cpuid_max(0,nullptr) || !__get_cpuid(1,&a,&b,&c,&d) || !(c & bit_AES))
        fail("AES instructions not available\n");

    {
        buffer_t in{'T','w','o',' ','O','n','e',' ','N','i','n','e',' ','T','w','o'};
        block_t key{__builtin_bswap64(0x5468617473206D79ull),__builtin_bswap64(0x204B756E67204675ull)};
        buffer_t out;
        buffer_t expect{0x29,0xC3,0x50,0x5F,0x57,0x14,0x20,0xF6,0x40,0x22,0x99,0xB3,0x1A,0x02,0xD7,0x3A};
        aes_encode(in,key,out);
        assert(out==expect);
        buffer_t dec;
        aes_decode(out,key,dec);
        assert(dec==in);
    }

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
