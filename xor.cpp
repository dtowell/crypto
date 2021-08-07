#include "crypto.h"

using namespace crypto;

void fail(std::string msg) 
{
    std::cout << msg;
    exit(1);
}

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
    if (!read_file(argv[2],buffer))
        fail(std::string("error reading from ")+argv[2]+"\n");
    for (size_t i=0; i<buffer.size(); ++i)
        buffer[i] = buffer[i] ^ key[i%key.size()];
    if (!write_file(argv[3],buffer))
        fail(std::string("error writing to ")+argv[3]+"\n");
}
