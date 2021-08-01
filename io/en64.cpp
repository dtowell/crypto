#include "crypto.h"

using namespace crypto;

int main(int argc,char *argv[])
{
    if (argc != 3) 
        fail(std::string("usage: ")+argv[0]+" infile outfile\n");

    buffer_t buffer;
    read_file(argv[1],buffer);
    std::string encoded;
    encode_base64(buffer,encoded);
    std::ofstream out(argv[2]);
    out << encoded;
}
