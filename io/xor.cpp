#include "crypto.h"

using namespace crypto;

int main(int argc,char *argv[])
{
    if (argc != 4) 
        fail(std::string("usage: ")+argv[0]+" hexkey infile outfile\n");

    std::stringstream ss(argv[1]);
    buffer_t key;
    uint8_t byte;
    while (ss >> std::setw(2) >> std::hex >> byte)
        key.push_back(byte);

    buffer_t buffer;
    read_file(argv[2],buffer);
    for (size_t i=0; i<buffer.size(); ++i)
        buffer[i] = buffer[i] ^ key[i%key.size()];
    write_file(argv[3],buffer);
}
