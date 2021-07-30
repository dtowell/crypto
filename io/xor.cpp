#include <iostream>
#include <fstream>
#include <string>
#include <stdint.h>

void fail(std::string msg) {
    std::cout << msg;
    exit(1);
}

int main(int argc,char *argv[])
{
    if (argc != 4) 
        fail(std::string("usage: ")+argv[0]+" hexkey infile outfile\n");

    uint32_t key = (uint32_t)std::stoul(argv[1],nullptr,16);
    std::ifstream in(argv[2],std::ifstream::binary);
    if (!in) 
        fail(std::string("error opening ")+argv[2]+"\n");
    std::ofstream out(argv[3],std::ofstream::binary);
    if (!out) 
        fail(std::string("error opening ")+argv[3]+"\n");

    uint32_t bytes;
    while (!in.eof()) {
        in.read((char *)&bytes,4);
        bytes ^= key;
        out.write((char *)&bytes,in.gcount());
    }
}
