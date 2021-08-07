#include "crypto.h"

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

    std::ifstream in(argv[1]);
    if (!in)
        fail(std::string("error opening ")+argv[1]+"\n");
    std::string input;
    std::string line;
    while (std::getline(in,line))
        input += line;

    buffer_t buffer;
    decode_base64(input,buffer);

    std::vector<buffer_t> fields;
    decode_rsakey(buffer,fields);

    for (int i=0; i<9; ++i)
        std::cout << fields[i];
}
