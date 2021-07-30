#include <iostream>
#include <fstream>
#include <iomanip>
#include <random>
#include <stdint.h>
#include <cpuid.h>
#include <immintrin.h>
using namespace std;

void fail(string msg) {
    cout << msg;
    exit(1);
}

int main(int argc,char *argv[])
{
    if (argc < 2) 
        fail(string("usage: ")+argv[0]+" <dev|rdrand|rdseed|prng|lcg> [bytes]\n");

    int bytes = argc>2 ? stoi(argv[2]) : 32;
    uint8_t *buffer = new uint8_t[(bytes+3)&~3]; // round up

    if (string(argv[1]) == "dev") {
        ifstream in("/dev/urandom",ifstream::binary);
        if (!in) 
            fail("error opening /dev/urandom\n");
        if (!in.read((char *)buffer,bytes))
            fail("error reading /dev/urandom\n");
    }
    else if (string(argv[1]) == "rdrand") {
        uint32_t a,b,c,d;
        if (!__get_cpuid_max(0,nullptr) || !__get_cpuid(0,&a,&b,&c,&d) || !(c & bit_RDRND))
            fail("rdrand not available\n");
        for (int i=0; i<bytes; i+=4)
            if (!_rdrand32_step((uint *)(buffer+i)))
                fail("rdrand not available\n");
    }
    else if (string(argv[1]) == "rdseed") {
        uint32_t a,b,c,d;
        if (!__get_cpuid_max(0,nullptr) || !__get_cpuid(7,&a,&b,&c,&d) || !(b & bit_RDSEED))
            fail("rdrand not available\n");
        for (int i=0; i<bytes; i+=4)
            if (!_rdseed32_step((uint *)(buffer+i)))
                fail("rdseed not available\n");
    }
    else if (string(argv[1]) == "prng") {
        random_device roll;
        for (int i=0; i<bytes; i+=4)
            *(uint32_t *)(buffer+i) = roll();
    }
    else if (string(argv[1]) == "lcg") {
        uint64_t seed = 0;
        for (int i=0; i<bytes; i+=4)
            *(uint32_t *)(buffer+i) = (uint32_t)((seed=(seed*6364136223846793005UL+1UL))>>16UL);
    }
    else
        fail("unknown source: "+string(argv[1]));
    
    for (int i=0; i<bytes; i++) {
        if (i%16 == 0)
            cout << setw(4) << setfill(' ') << hex << i << ":";
        cout << " " << setw(2) << setfill('0') << hex << +buffer[i];
        if (i%16 == 15)
            cout << "\n";
    }
    if (bytes%16)
        cout << "\n";
    
    delete [] buffer;
}