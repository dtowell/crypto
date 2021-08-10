#include "crypto.h"
#include <cpuid.h>

using namespace crypto;

void fail(std::string msg) 
{
    std::cout << msg;
    exit(1);
}

int main(int argc,char *argv[])
{
    if (argc != 2) 
        fail(std::string("usage: ")+argv[0]+" infile\n");

    buffer_t plain;
    if (!read_file(argv[1],plain))
        fail(std::string("error reading from ")+argv[3]+"\n");

    buffer_t hash;
    if (!hash_sha512(plain,hash))
        fail("hasing failed\n");

    std::cout << hash;
}
