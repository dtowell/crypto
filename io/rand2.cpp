#include <iostream>
#include <fstream>
#include <iomanip>
#include <random>
#include <vector>
#include <stdint.h>
#include <cpuid.h>
#include <immintrin.h>

using buffer_t = std::vector<uint8_t>;

void output_hex(const buffer_t &buffer) {
    for (int i=0; i<buffer.size(); i++) {
        if (i%16 == 0)
            std::cout << std::setw(4) << std::setfill(' ') << std::hex << i << ":";
        std::cout << " " << std::setw(2) << std::setfill('0') << std::hex << +buffer[i];
        if (i%16 == 15)
            std::cout << "\n";
    }
    if (buffer.size()%16)
        std::cout << "\n";
}

void fail(std::string msg) {
    std::cout << msg;
    exit(1);
}

int main(int argc,char *argv[])
{
    if (argc < 2) 
        fail(std::string("usage: ")+argv[0]+" <dev|rdrand|rdseed|prng|lcg> [bytes]\n");

    int bytes = argc>2 ? std::stoi(argv[2]) : 32;
    buffer_t buffer((bytes+3)&~3); // round up to multiple of 4

    if (std::string(argv[1]) == "dev") {
        std::ifstream in("/dev/urandom",std::ifstream::binary);
        if (!in)
            fail("error opening /dev/urandom\n");
        if (!in.read((char *)&buffer[0],buffer.size()))
            fail("error reading /dev/urandom\n");
    }
    else if (std::string(argv[1]) == "rdrand") {
        uint32_t a,b,c,d;
        if (!__get_cpuid_max(0,nullptr) || !__get_cpuid(0,&a,&b,&c,&d) || !(c & bit_RDRND))
            fail("rdrand not available\n");
        for (int i=0; i<bytes; i+=4)
            if (!_rdrand32_step((uint32_t *)(&buffer[i])))
                fail("rdrand not available\n");
    }
    else if (string(argv[1]) == "rdseed") {
        uint32_t a,b,c,d;
        if (!__get_cpuid_max(0,nullptr) || !__get_cpuid(7,&a,&b,&c,&d) || !(b & bit_RDSEED))
            fail("rdrand not available\n");
        for (int i=0; i<bytes; i+=4)
            if (!_rdseed32_step((uint32_t *)(&buffer[i])))
                fail("rdseed not available\n");
    }
    else if (string(argv[1]) == "prng") {
        std::random_device roll;
        for (int i=0; i<bytes; i+=4)
            *(uint32_t *)(&buffer[i]) = roll();
    }
    else if (string(argv[1]) == "lcg") {
        uint64_t seed = 0;
        for (int i=0; i<bytes; i+=4)
            *(uint32_t *)(&buffer[i]) = (uint32_t)((seed=(seed*6364136223846793005UL+1UL))>>16UL);
    }
    else
        fail("unknown source: "+string(argv[1]));

    output_hex(buffer);
}
