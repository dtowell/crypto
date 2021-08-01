#include "crypto.h"

using namespace crypto;

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

    buffer_t plain;
    read_file(argv[2],plain);
    while (plain.size()%sizeof(block_t) != 0)
        plain.push_back(0);

    buffer_t encoded;
    aes_encode(plain,*(block_t *)&key[0],encoded);

    write_file(argv[3],encoded);
}
