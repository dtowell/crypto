#include "crypto.h"

using namespace crypto;

void fail(std::string msg) 
{
    std::cout << msg;
    exit(1);
}

int main(int argc,char *argv[])
{
    if (argc != 3) 
        fail(std::string("usage: ")+argv[0]+" infile outfile\n");

    buffer_t buffer;
    if (!read_file(argv[1],buffer))
        fail(std::string("error reading from ")+argv[1]);
    std::string encoded;
    encode_base64(buffer,encoded);
    std::ofstream out(argv[2]);
    out << encoded;
}
