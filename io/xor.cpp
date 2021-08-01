#include <iostream>
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>
#include <stdint.h>

using buffer_t = std::vector<uint8_t>;

void fail(std::string msg) {
    std::cout << msg;
    exit(1);
}

void read_file(std::string filename,buffer_t &buffer) {
    std::ifstream in(filename,std::ifstream::binary);
    if (!in) 
        fail(std::string("error opening ")+filename+"\n");
    in.seekg(0,std::ios::end);
    buffer.resize(in.tellg());
    in.seekg(0,std::ios::beg);
    in.read(reinterpret_cast<char *>(&buffer[0]),buffer.size());
}

void write_file(std::string filename,const buffer_t &buffer) {
    std::ofstream out(filename,std::ofstream::binary);
    if (!out) 
        fail(std::string("error opening ")+filename+"\n");
    
    out.write(reinterpret_cast<const char *>(&buffer[0]),buffer.size());
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
    read_file(argv[2],buffer);
    for (size_t i=0; i<buffer.size(); ++i)
        buffer[i] = buffer[i] ^ key[i%key.size()];
    write_file(argv[3],buffer);
}
