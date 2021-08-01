#include "crypto.h"

using namespace crypto;

int main(int argc,char *argv[])
{
    if (argc != 3) 
        fail(std::string("usage: ")+argv[0]+" infile outfile\n");

    std::ifstream in(argv[1]);
    if (!in)
        fail(std::string("error opening ")+argv[1]+"\n");
    std::string input;
    std::string line;
    while (std::getline(in,line))
        input += line;

    buffer_t buffer;
    decode_base64(input,buffer);
    write_file(argv[2],buffer);
}
