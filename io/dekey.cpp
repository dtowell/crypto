#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <memory>
#include <cstddef>

using buffer_t = std::vector<uint8_t>;

void fail(std::string msg) {
    std::cout << msg;
    exit(1);
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

void output_hex(const buffer_t &buffer) {
    for (size_t i=0; i<buffer.size(); i++) {
        if (i%16 == 0)
            std::cout << std::setw(4) << std::setfill(' ') << std::hex << i << ":";
        std::cout << " " << std::setw(2) << std::setfill('0') << std::hex << +buffer[i];
        if (i%16 == 15)
            std::cout << "\n";
    }
    if (buffer.size()%16)
        std::cout << "\n";
}

void decode_rsakey(const buffer_t &buffer,std::vector<buffer_t> &fields) {
    fields.resize(0);
    size_t i=0;
    if (buffer[i++] != 0x30) fail("not sequence type\n");
    if (buffer[i++] != 0x82) fail("length of sequence type wrong\n");
    size_t s = buffer[i]<<8 | buffer[i+1];
    if (s != buffer.size()-4) fail("data wrong length\n");
    i+=2;

    for (int j=0; j<9; j++) {
        if (buffer[i++] != 0x02) fail("expecting primitive integer type\n");
        size_t len = buffer[i++];
        if (len >= 0x80) {
            if (len != 0x82) fail("length of length is wrong\n");
            len = buffer[i]<<8 | buffer[i+1];
            i+=2;
        }
        std::vector<uint8_t> t(len);
        for (size_t k=0; k<len; k++)
            t[k] = buffer[i++];
        fields.push_back(t);
    }
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
        output_hex(fields[i]);

/*
    version           Version,
    modulus           INTEGER,  -- n
    publicExponent    INTEGER,  -- e
    privateExponent   INTEGER,  -- d
    prime1            INTEGER,  -- p
    prime2            INTEGER,  -- q
    exponent1         INTEGER,  -- d mod (p-1)
    exponent2         INTEGER,  -- d mod (q-1)
    coefficient       INTEGER,  -- (inverse of q) mod p
*/
}
