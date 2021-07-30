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

void read_file(std::string filename,buffer_t &buffer) {
    std::ifstream in(filename,std::ifstream::binary);
    if (!in) 
        fail(std::string("error opening ")+filename+"\n");
    in.seekg(0,std::ios::end);
    buffer.resize(in.tellg());
    in.seekg(0,std::ios::beg);
    in.read(reinterpret_cast<char *>(&buffer[0]),buffer.size());
}

void encode_base64(const buffer_t &plain,std::string &encoded) {
    static const char * base64 = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "+/";

    encoded.clear();
    for (size_t i=0; i<plain.size(); i+=3) {
        if (i && i % 57 == 0)
            encoded += '\n';

        encoded += base64[plain[i] >> 2];

        if (i+1 < plain.size()) {
            encoded += base64[((plain[i] & 0x03) << 4) + (plain[i+1] >> 4)];

            if (i+2 < plain.size()) {
                encoded += base64[((plain[i+1] & 0x0f) << 2) + ((plain[i+2] & 0xc0) >> 6)];
                encoded += base64[  plain[i+2] & 0x3f];
            }
            else {
                encoded += base64[(plain[i+1] & 0x0f) << 2];
                encoded += '=';
            }
        }
        else {
            encoded += base64[(plain[i] & 0x03) << 4];
            encoded += '=';
            encoded += '=';
        }
    }
    encoded += '\n';
}

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
