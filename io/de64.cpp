#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <memory>
#include <cstddef>

using buffer_t = std::vector<uint8_t>;

void fail(std::string msg) {
    std::cout << msg;
    exit(1);
}

void write_file(std::string filename,const buffer_t &buffer) {
    std::ofstream out(filename,std::ofstream::binary);
    if (!out) 
        fail(std::string("error opening ")+filename+"\n");
    
    out.write(reinterpret_cast<const char *>(&buffer[0]),buffer.size());
}

void decode_base64(const std::string &encoded,buffer_t &buffer) {
    static const int base64[256] =
    {
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  62, 63, 62, 62, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0,  0,  0,  0,  0,  0,
        0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0,  0,  0,  0,  63,
        0,  26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
    };

    size_t size = encoded.size();
    size_t pad1 = size % 4 || encoded[size-1] == '=';
    size_t pad2 = pad1 && (size % 4 > 2 || encoded[size-2] != '=');
    const size_t last = (encoded.size()-pad1)/4 << 2;

    buffer.resize(0);
    for (size_t i=0; i<last; i+=4) {
        uint32_t n = base64[(uint8_t)encoded[i]] << 18 
              | base64[(uint8_t)encoded[i+1]] << 12 
              | base64[(uint8_t)encoded[i+2]] << 6 
              | base64[(uint8_t)encoded[i+3]];
        buffer.push_back((uint8_t)(n >> 16));
        buffer.push_back((uint8_t)(n >> 8 & 0xFF));
        buffer.push_back((uint8_t)(n & 0xFF));
    }
    if (pad1) {
        uint32_t n = base64[(uint8_t)encoded[last]] << 18 | base64[(uint8_t)encoded[last+1]] << 12;
        buffer.push_back((uint8_t)(n >> 16));
        if (pad2) {
            n |= base64[(uint8_t)encoded[last+2]] << 6;
            buffer.push_back((uint8_t)(n >> 8 & 0xFF));
        }
    }
}

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
