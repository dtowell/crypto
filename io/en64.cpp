#include <iostream>
#include <fstream>
#include <string>
#include <memory>
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

    auto begin = in.tellg();
    auto size = in.seekg(0, std::ios::end).tellg() - begin;
    in.seekg(0,std::ios::beg);

    std::unique_ptr<byte[]> contents(new byte[size]);
    in.read(reinterpret_cast<char *>(contents.get()),size);
    if (in.gcount() != size)
        fail("read failed");
    
    static const char * base64 = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "+/";

    for (int i=0; i<size; i+=3) {
        if (i && i % 57 == 0)
            out << "\n";

        out << base64[contents[i] >> 2];

        if (i+1 < size) {
            out << base64[((contents[i] & 0x03) << 4) + (contents[i+1] >> 4)];

            if (i+2 < size) {
                out << base64[((contents[i+1] & 0x0f) << 2) + ((contents[i+2] & 0xc0) >> 6)];
                out << base64[  contents[i+2] & 0x3f];
            }
            else {
                out << base64[(contents[i+1] & 0x0f) << 2];
                out << "=";
            }
        }
        else {
            out << base64[(contents[i] & 0x03) << 4];
            out << "=";
            out << "=";
        }
    }
    out << "\n";
}
