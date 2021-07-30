#include <iostream>
#include <fstream>
#include <string>
#include <memory>
#include <vector>
#include <cstddef>
using byte = unsigned char;

void fail(std::string msg) {
    std::cout << msg;
    exit(1);
}

int main(int argc,char *argv[])
{
    if (argc != 3) 
        fail(std::string("usage: ")+argv[0]+" infile outfile\n");

    std::ifstream in(argv[1],std::ifstream::binary);
    if (!in) 
        fail(std::string("error opening ")+argv[1]+"\n");
    std::ofstream out(argv[2],std::ofstream::binary);
    if (!out) 
        fail(std::string("error opening ")+argv[2]+"\n");

    std::string input;
    std::string line;
    while (std::getline(in,line))
        input += line;

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

    byte *p = reinterpret_cast<byte *>(&input[0]);
    size_t size = input.size();
    size_t pad1 = size % 4 || p[size-1] == '=';
    size_t pad2 = pad1 && (size % 4 > 2 || p[size-2] != '=');
    const size_t last = (size-pad1)/4 << 2;
    std::vector<byte> result;
    for (size_t i=0; i<last; i+=4) {
        int n = base64[p[i]] << 18 
              | base64[p[i+1]] << 12 
              | base64[p[i+2]] << 6 
              | base64[p[i+3]];
        result.push_back(byte(n >> 16));
        result.push_back(byte(n >> 8 & 0xFF));
        result.push_back(byte(n & 0xFF));
    }
    if (pad1) {
        int n = base64[p[last]] << 18 | base64[p[last+1]] << 12;
        result.push_back(byte(n >> 16));
        if (pad2) {
            n |= base64[p[last+2]] << 6;
            result.push_back(byte(n >> 8 & 0xFF));
        }
    }

    for (auto c:result)
        out << c;
}
