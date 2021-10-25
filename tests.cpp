#include "crypto.h"

using namespace crypto;

int main()
{
    {
        buffer_t x;
        assert(read_file("missing.txt",x) == false);
        assert(read_file("samp.txt",x));
        buffer_t expect{'T','w','o',' ','O','n','e',' ','N','i','n','e',' ','T','w','o'};
        assert(x==expect);
    }

    {
        buffer_t x{'j','u','n','k'};
        assert(write_file("bogus",x));
        buffer_t y;
        assert(read_file("bogus",y));
        assert(x==y);
        system("rm bogus");
    }

    {
        buffer_t x;
        buffer_t hash;
        assert(hash_sha256(x,hash));
        // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        // https://en.wikipedia.org/wiki/SHA-2
        buffer_t expect{0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55};
        assert(hash==expect);
    }

    {
        buffer_t x{'a','b','c'};
        buffer_t hash;
        assert(hash_sha256(x,hash));
        // BA7816BF 8F01CFEA 414140DE 5DAE2223 B00361A3 96177A9C B410FF61 F20015AD
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
        buffer_t expect{ 0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23, 0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD,};
        assert(hash==expect);
    }

    {
        buffer_t x{'a','b','c','d','b','c','d','e','c','d','e','f','d','e','f','g','e','f','g','h','f','g','h','i','g','h','i','j','h','i','j','k','i','j','k','l','j','k','l','m','k','l','m','n','l','m','n','o','m','n','o','p','n','o','p','q'};
        buffer_t hash;
        assert(hash_sha256(x,hash));
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
        buffer_t expect{ 0x24, 0x8D, 0x6A, 0x61 , 0xD2, 0x06, 0x38, 0xB8 , 0xE5, 0xC0, 0x26, 0x93 , 0x0C, 0x3E, 0x60, 0x39 , 0xA3, 0x3C, 0xE4, 0x59 , 0x64, 0xFF, 0x21, 0x67 , 0xF6, 0xEC, 0xED, 0xD4 , 0x19, 0xDB, 0x06, 0xC1 };
        assert(hash==expect);
    }



    {
        buffer_t x;
        buffer_t hash;
        assert(hash_sha512(x,hash));
        // cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
        // https://en.wikipedia.org/wiki/SHA-2
        buffer_t expect{0xcf,0x83,0xe1,0x35,0x7e,0xef,0xb8,0xbd,0xf1,0x54,0x28,0x50,0xd6,0x6d,0x80,0x07,0xd6,0x20,0xe4,0x05,0x0b,0x57,0x15,0xdc,0x83,0xf4,0xa9,0x21,0xd3,0x6c,0xe9,0xce,0x47,0xd0,0xd1,0x3c,0x5d,0x85,0xf2,0xb0,0xff,0x83,0x18,0xd2,0x87,0x7e,0xec,0x2f,0x63,0xb9,0x31,0xbd,0x47,0x41,0x7a,0x81,0xa5,0x38,0x32,0x7a,0xf9,0x27,0xda,0x3e};
        assert(hash==expect);
    }

    {
        buffer_t x{'a','b','c'};
        buffer_t hash;
        assert(hash_sha512(x,hash));
        // DDAF35A1 93617ABA CC417349 AE204131 12E6FA4E 89A97EA2 0A9EEEE6 4B55D39A 2192992A 274FC1A8 36BA3C23 A3FEEBBD 454D4423 643CE80E 2A9AC94F A54CA49F
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf
        buffer_t expect{ 0xDD,0xAF,0x35,0xA1 ,0x93,0x61,0x7A,0xBA ,0xCC,0x41,0x73,0x49 ,0xAE,0x20,0x41,0x31 ,0x12,0xE6,0xFA,0x4E ,0x89,0xA9,0x7E,0xA2 ,0x0A,0x9E,0xEE,0xE6 ,0x4B,0x55,0xD3,0x9A ,0x21,0x92,0x99,0x2A ,0x27,0x4F,0xC1,0xA8 ,0x36,0xBA,0x3C,0x23 ,0xA3,0xFE,0xEB,0xBD ,0x45,0x4D,0x44,0x23 ,0x64,0x3C,0xE8,0x0E ,0x2A,0x9A,0xC9,0x4F ,0xA5,0x4C,0xA4,0x9F};
        assert(hash==expect);
    }

    {
        std::string msg{"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"};
        buffer_t x(msg.begin(),msg.end());
        buffer_t hash;
        assert(hash_sha512(x,hash));
        // 8E959B75 DAE313DA 8CF4F728 14FC143F 8F7779C6 EB9F7FA1 7299AEAD B6889018 501D289E 4900F7E4 331B99DE C4B5433A C7D329EE B6DD2654 5E96E55B 874BE909
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf
        buffer_t expect{ 0x8E,0x95,0x9B,0x75,0xDA,0xE3,0x13,0xDA,0x8C,0xF4,0xF7,0x28,0x14,0xFC,0x14,0x3F,0x8F,0x77,0x79,0xC6,0xEB,0x9F,0x7F,0xA1,0x72,0x99,0xAE,0xAD,0xB6,0x88,0x90,0x18,0x50,0x1D,0x28,0x9E,0x49,0x00,0xF7,0xE4,0x33,0x1B,0x99,0xDE,0xC4,0xB5,0x43,0x3A,0xC7,0xD3,0x29,0xEE,0xB6,0xDD,0x26,0x54,0x5E,0x96,0xE5,0x5B,0x87,0x4B,0xE9,0x09 };
        assert(hash==expect);
    }

    {
        buffer_t x{'a','b','c'};
        buffer_t hash;
        assert(hash_sha512_256(x,hash));
        // 53048E26 81941EF9 9B2E29B7 6B4C7DAB E4C2D0C6 34FC6D46 E0E2F131 07E7AF23
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_256.pdf
        buffer_t expect{0x53,0x04,0x8E,0x26,0x81,0x94,0x1E,0xF9,0x9B,0x2E,0x29,0xB7,0x6B,0x4C,0x7D,0xAB,0xE4,0xC2,0xD0,0xC6,0x34,0xFC,0x6D,0x46,0xE0,0xE2,0xF1,0x31,0x07,0xE7,0xAF,0x23};
        assert(hash==expect);
    }

    {
        buffer_t x;
        buffer_t hash;
        assert(hash_sha512_256(x,hash));
        // c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a
        // https://en.wikipedia.org/wiki/SHA-2
        buffer_t expect{0xc6,0x72,0xb8,0xd1,0xef,0x56,0xed,0x28,0xab,0x87,0xc3,0x62,0x2c,0x51,0x14,0x06,0x9b,0xdd,0x3a,0xd7,0xb8,0xf9,0x73,0x74,0x98,0xd0,0xc0,0x1e,0xce,0xf0,0x96,0x7a};
        assert(hash==expect);
    }

    {
        buffer_t in{'a','n','y',' ','c','a','r','n','a','l',' ','p','l','e','a','s'};
        std::string enc;
        buffer_t dec;

        encode_base64(in,enc);
        enc.pop_back();
        assert(enc=="YW55IGNhcm5hbCBwbGVhcw==");
        decode_base64(enc,dec);
        assert(dec==in);

        in.push_back('u');
        encode_base64(in,enc);
        enc.pop_back();
        assert(enc=="YW55IGNhcm5hbCBwbGVhc3U=");
        decode_base64(enc,dec);
        assert(dec==in);

        in.push_back('r');
        encode_base64(in,enc);
        enc.pop_back();
        assert(enc=="YW55IGNhcm5hbCBwbGVhc3Vy");
        decode_base64(enc,dec);
        assert(dec==in);

        in.push_back('e');
        encode_base64(in,enc);
        enc.pop_back();
        assert(enc=="YW55IGNhcm5hbCBwbGVhc3VyZQ==");
        decode_base64(enc,dec);
        assert(dec==in);

        in.push_back('.');
        encode_base64(in,enc);
        enc.pop_back();
        assert(enc=="YW55IGNhcm5hbCBwbGVhc3VyZS4=");
        decode_base64(enc,dec);
        assert(dec==in);
    }

    {
        buffer_t in{'T','w','o',' ','O','n','e',' ','N','i','n','e',' ','T','w','o'};
        block_t key{__builtin_bswap64(0x5468617473206D79ull),__builtin_bswap64(0x204B756E67204675ull)};
        buffer_t out;
        buffer_t expect{0x29,0xC3,0x50,0x5F,0x57,0x14,0x20,0xF6,0x40,0x22,0x99,0xB3,0x1A,0x02,0xD7,0x3A};
        assert(encode_aes_ecb(in,key,out));
        assert(out==expect);
        buffer_t dec;
        assert(decode_aes_ecb(out,key,dec));
        assert(dec==in);
    }

    { 
        assert(is_prime(2));
        assert(is_prime(3));
        assert(is_prime(5));
        assert(is_prime(7));
        assert(is_prime(11));
        assert(is_prime(13));
        assert(is_prime(17));
        assert(is_prime(19));
        assert(is_prime(23));
        assert(is_prime(29));
        assert(is_prime(31));
        assert(is_prime(65537));

        assert(!is_prime(4));
        assert(!is_prime(6));
        assert(!is_prime(8));
        assert(!is_prime(9));
        assert(!is_prime(10));
        assert(!is_prime(12));
        assert(!is_prime(14));
        assert(!is_prime(15));
        assert(!is_prime(16));
        assert(!is_prime(18));
        assert(!is_prime(20));
        assert(!is_prime(65536));
    }

    {
        assert(next_prime(3) == 5);
        assert(next_prime(4) == 5);
        assert(next_prime(13) == 17);
        assert(next_prime(65534) == 65537);
    }

    {
        for (int i=1; i<100000; i++) {
            assert(pow_mod(1,i,10000000)==1);
            assert(pow_mod(1,i,1001)==1);
            assert(pow_mod(1,i,3)==1);
            assert(pow_mod(2,i,2)==0);
        }
        assert(pow_mod(3,3,10000)==27);
        assert(pow_mod(3,5,10000)==81*3);
        assert(pow_mod(7,5,1000)==(7*7*7*7*7) % 1000);
    }

    { // https://www.di-mgt.com.au/rsa_alg.html
        rsa_private_t key;
        key.p=11;
        key.q=3;
        key.e=3;
        key.d=7;
        assert(is_prime(key.p));
        assert(is_prime(key.q));
        assert(key.p != key.q);
        auto n = key.p*key.q;
        assert(!is_prime(n));
        
        assert(pow_mod(pow_mod(0,key.e,n),key.d,n)==0);
        assert(pow_mod(pow_mod(1,key.e,n),key.d,n)==1);
        assert(pow_mod(pow_mod(2,key.e,n),key.d,n)==2);
        assert(pow_mod(7,key.e,n)==13);
        assert(pow_mod(13,key.d,n)==7);

        uint64_t encoded[] = {0,1,8,27,31,26,18,13,17,3,10,11,12,19,5,9,4,29,24,28,14,21,22,23,30,16,20,15,7,2,6,25,32};
        for (uint64_t m=0; m<33; m++)
            assert(pow_mod(m,key.e,n)==encoded[m]);
        for (uint64_t m=0; m<33; m++)
            assert(pow_mod(pow_mod(m,key.e,n),key.d,n)==m);
    }

    { // https://www.di-mgt.com.au/rsa_alg.html
        rsa_private_t key;
        key.p=173;
        key.q=149;
        key.e=3;
        key.d=16971;
        assert(is_prime(key.p));
        assert(is_prime(key.q));
        assert(key.p != key.q);
        auto n = key.p*key.q;
        assert(!is_prime(n));
        assert(inv_mod(key.e,(key.p-1)*(key.q-1))==key.d);

        assert(pow_mod( 1289,key.e,n)==18524);
        assert(pow_mod(  821,key.e,n)== 7025);
        assert(pow_mod(   47,key.e,n)==  715);
        assert(pow_mod(  518,key.e,n)== 2248);
        assert(pow_mod(16187,key.e,n)==24465);

        rsa_public_t pub;
        assert(rsa_publish(key,pub));
        uint64_t encoded;
        assert(rsa_encode( 1289,pub,encoded)); assert(encoded == 18524);
        assert(rsa_encode(  821,pub,encoded)); assert(encoded ==  7025);
        assert(rsa_encode(   47,pub,encoded)); assert(encoded ==   715);
        assert(rsa_encode(  518,pub,encoded)); assert(encoded ==  2248);
        assert(rsa_encode(16187,pub,encoded)); assert(encoded == 24465);

        uint64_t decoded;
        assert(rsa_decode(18524,key,decoded)); assert(decoded ==  1289);
        assert(rsa_decode( 7025,key,decoded)); assert(decoded ==   821);
        assert(rsa_decode(  715,key,decoded)); assert(decoded ==    47);
        assert(rsa_decode( 2248,key,decoded)); assert(decoded ==   518);
        assert(rsa_decode(24465,key,decoded)); assert(decoded == 16187);
    }

    {
        rsa_private_t key;
        assert(rsa_generate(key));
        assert(is_prime(key.p));
        assert(is_prime(key.q));
        assert(key.p != key.q);
        auto n = key.p*key.q;
        assert(!is_prime(n));
        //std::cout << std::hex << key.p << " " << std::hex << key.q << "\n";

        assert(pow_mod(pow_mod(0,key.e,n),key.d,n)==0);
        assert(pow_mod(pow_mod(1,key.e,n),key.d,n)==1);
        assert(pow_mod(pow_mod(2,key.e,n),key.d,n)==2);

        for (uint64_t i=0; i<10000; i++)
            assert(pow_mod(pow_mod(i,key.e,n),key.d,n)==i);

        rsa_public_t pub;
        assert(rsa_publish(key,pub));
        assert(pub.n = key.p*key.q);
        assert(!is_prime(pub.n));
        assert(is_prime(pub.e));
        assert(pub.e == 65537);
    }

#if 0
    {
        nni_t a;
        assert(format(a) == "0");
        set(a,7);
        assert(digit(a,0) == 7);
        assert(a.size() == 1);
        set(a,123456789012345);
        assert(digit(a,0) == 123456789012345);
        assert(a.size() == 1);
        set(a,"1");
        assert(digit(a,0) == 1);
        assert(a.size() == 1);
        set(a,"3");
        assert(digit(a,0) == 3);
        assert(a.size() == 1);

        nni_t b;
        multiply(b,a,a);
        assert(digit(b,0) == 9);
        assert(b.size()==1);

        nni_t c;
        multiply(c,b,a);
        assert(digit(c,0) == 27);
        assert(b.size()==1);

        set(a,"12");
        assert(digit(a,0) == 12);
        assert(a.size() == 1);
        set(a,"123456789012345678901234567890");
        assert(a.size() == 2);
        set(a,"123");
        assert(digit(a,0) == 123);
        assert(a.size() == 1);
    }

    {
        nni_t a;
        assert(format(a) == "0");
        set(a,7);
        assert(format(a) == "7");
        set(a,123456789012345);
        assert(format(a) == "123456789012345");
    }

    {
        nni_t a;
        assert(format(a) == "0");
        set(a,"99");
        assert(format(a) == "99");
        set(a,"1234567890123456789012345678901234567890");
        assert(format(a) == "1234567890123456789012345678901234567890");
    }

    {
        nni_t a;
        set(a,1);
        shiftleft(a,1);
        assert(format(a) == "2");
        shiftleft(a,1);
        assert(format(a) == "4");
        shiftleft(a,1);
        assert(format(a) == "8");
        shiftleft(a,1);
        assert(format(a) == "16");
        shiftleft(a,4);
        assert(format(a) == "256");
        shiftleft(a,8);
        assert(format(a) == "65536");
        shiftleft(a,16);
        assert(format(a) == "4294967296");
        shiftleft(a,32);
        assert(a.size()==2);
        assert(a[0]==0);
        assert(a[1]==1);
        shiftright(a,1);
        assert(a.size()==1);
        shiftright(a,63);
        assert(a.size()==1);
        assert(a[0]==1);
        shiftright(a,1);
        assert(a.size()==0);
    }

    {
        nni_t a,b,c,d;

        set(a,1);
        shiftleft(a,1);
        shiftleft(a,63);

        set(b,7);
        shiftleft(b,2);
        shiftleft(b,62);

        add(c,a,b);
        assert(c.size()==2);
        assert(c[0]==0);
        assert(c[1]==8);

        set(a,10000);
        shiftleft(a,62);
        shiftleft(a,2);
        set(b,30000);
        shiftleft(b,32);
        shiftleft(b,32);
        set(c,1234);
        add(d,a,c);         // d = 10000<<64 + 1234
        add(a,b,c);         // a = 30000<<64 + 1234
        add(b,a,d);         // b = 40000<<64 + 1234*2
        assert(b.size()==2);
        assert(b[0] == 1234*2);
        assert(b[1]==40000);
    }

    {
        nni_t a,b,c,d;

        set(a,1);
        shiftleft(a,1);
        shiftleft(a,63);

        set(b,7);
        shiftleft(b,2);
        shiftleft(b,62);

        subtract(c,b,a);
        assert(c.size()==2);
        assert(c[0]==0);
        assert(c[1]==6);

        set(a,10000);
        shiftleft(a,62);
        shiftleft(a,2);
        set(b,30000);
        shiftleft(b,32);
        shiftleft(b,32);
        set(c,1234);
        add(d,a,c);         // d = 10000<<64 + 1234
        add(a,b,c);         // a = 30000<<64 + 1234
        subtract(b,a,d);    // b = 20000<<64 + 0
        assert(b.size()==2);
        assert(b[0] == 0);
        assert(b[1]==20000);
    }

    {
        nni_t a,b,c,d;

        set(a,3);
        shiftleft(a,1);
        shiftleft(a,63);

        set(b,7);
        shiftleft(b,2);
        shiftleft(b,62);

        multiply(c,b,a);
        assert(c.size()==3);
        assert(c[0]==0);
        assert(c[0]==0);
        assert(c[2]==21);
    }

    {
        nni_t a,b,c;

        a.push_back(2);
        a.push_back(3);
        a.push_back(4);

        b.push_back(5);
        b.push_back(6);
        b.push_back(7);

        //          4   3   2
        //       x  7   6   5
        //       ------------
        //         20  15  10
        //     24  18  12
        // 28  21  14

        multiply(c,a,b);
        assert(c.size()==5);
        assert(c[0] == 2*5);
        assert(c[1] == 3*5+2*6);
        assert(c[2] == 4*5+6*3+7*2);
        assert(c[3] == 4*6+7*3);
        assert(c[4] == 4*7);
    }

    {
        nni_t a,b,c;

        a.push_back(1UL<<63);
        a.push_back(1UL<<63);
        a.push_back(1UL<<63);
        b.push_back(1UL<<63);
        b.push_back(1UL<<63);
        b.push_back(1UL<<63);

        //                    1000  1000  1000
        //                  x 1000  1000  1000
        //                  ------------------
        //               100  0100  0100  0000
        //        0100  0100  0100  0000
        //  0100  0100  0100  0000
        //  ----------------------------------
        //  0100  1000  1100  1000  0100  0000

        multiply(c,a,b);
        assert(c.size()==6);
        assert(c[0] == 0);
        assert(c[1] == 1UL<<62);
        assert(c[2] == 1UL<<63);
        assert(c[3] == 3UL<<62);
        assert(c[4] == 1UL<<63);
        assert(c[5] == 1UL<<62);
    }

    {
        nni_t a,b;

        set(a,1);
        set(b,1);
        assert(!lesser(a,b));
        assert(!lesser(b,a));

        set(a,1);
        set(b,2);
        assert(lesser(a,b));
        assert(!lesser(b,a));
        
        a.push_back(1);
        assert(lesser(b,a));
        assert(!lesser(a,b));

        b.push_back(1);
        assert(lesser(a,b));
        assert(!lesser(b,a));

        b.push_back(1);
        assert(!lesser(b,a));
        assert(lesser(a,b));

        set(a,0);
        set(b,0);
        assert(!lesser(b,a));
        assert(!lesser(a,b));
        set(a,1);
        assert(lesser(b,a));
        assert(!lesser(a,b));
    }

    {
        nni_t q,r,u,v;

        for (digit_t i=0; i<20; i++)
            for (digit_t j=1; j<25; j++) {
                set(u,i);
                set(v,j);
                divide(q,r,u,v);

                if (i/j) {
                    assert(q.size()==1);
                    assert(q[0]==i/j);
                }
                else 
                    assert(q.size()==0);

                if (i%j) {
                    assert(r.size()==1);
                    assert(r[0]==i%j);
                }
                else {
                    //std::cout << u << "\n";
                    //std::cout << v << "\n";
                    //std::cout << q << "\n";
                    //std::cout << r << "\n";
                    assert(r.size()==0);
                }
            }

        for (digit_t i=0; i<20; i++)
            for (digit_t j=1; j<25; j++) {
                set(u,0);
                if (i) {
                    u.push_back(0);
                    u.push_back(i);
                }
                set(v,0);
                if (j) {
                    v.push_back(0);
                    v.push_back(j);
                }
                divide(q,r,u,v);

                if (i/j) {
                    assert(q.size()==1);
                    assert(q[0]==i/j);
                }
                else 
                    assert(q.size()==0);

                if (i%j) {
                    assert(r.size()==2);
                    assert(r[0]==0);
                    assert(r[1]==i%j);
                }
                else {
                    assert(r.size()==0);
                }
            }

        for (digit_t i=0; i<20; i++)
            for (digit_t j=1; j<25; j++) {
                set(u,0);
                if (i) {
                    u.push_back(0);
                    u.push_back(0);
                    u.push_back(i);
                }
                set(v,0);
                if (j) {
                    v.push_back(0);
                    v.push_back(0);
                    v.push_back(j);
                }
                divide(q,r,u,v);

                if (i/j) {
                    assert(q.size()==1);
                    assert(q[0]==i/j);
                }
                else 
                    assert(q.size()==0);

                if (i%j) {
                    assert(r.size()==3);
                    assert(r[0]==0);
                    assert(r[1]==0);
                    assert(r[2]==i%j);
                }
                else {
                    assert(r.size()==0);
                }
            }

    }
    {
        nni_t r,a,e,b;
        set(a,2);
        set(e,64);
        set(b,"999999999999999999999999999999999999999");
        expmod(r,a,e,b);
        assert(r.size()==2);
        assert(r[0]==0);
        assert(r[1]==1);

        set(b,3);
        expmod(r,a,e,b);
        assert(r.size()==1);
        assert(r[0]==1);
    }
#endif

    {
        NNI a(7);
        assert(a.size() == 1);
        assert(a.digit(0) == 7);

        a = NNI(123456789012345);
        assert(a.digit(0) == 123456789012345);
        assert(a.size() == 1);
    }
    {
        NNI a("1");
        assert(a.digit(0) == 1);
        assert(a.size() == 1);
    }
    {
        NNI a("3");
        assert(a.digit(0) == 3);
        assert(a.size() == 1);

        NNI b;
        b = a*a;
        assert(b.digit(0) == 9);
        assert(b.size()==1);

        NNI c;
        c = b*a;
        assert(c.digit(0) == 27);
        assert(c.size()==1);
    }
    {
        NNI a("12");
        assert(a.digit(0) == 12);
        assert(a.size() == 1);
    }
    {
        NNI a("123");
        assert(a.digit(0) == 123);
        assert(a.size() == 1);
    }

    {
        NNI a;
        assert(a.format() == "0");
    }
    {
        NNI a(7);
        assert(a.format() == "7");
    }
    {
        NNI a(123456789012345);
        assert(a.format() == "123456789012345");
    }
    {
        NNI a(99);
        assert(a.format() == "99");
    }

    {
        NNI a(1);
        a <<= 1;
        assert(a.format() == "2");
        a <<= 1;
        assert(a.format() == "4");
        a <<= 1;
        assert(a.format() == "8");
        a <<= 1;
        assert(a.format() == "16");
        a <<= 4;
        assert(a.format() == "256");
        a <<= 8;
        assert(a.format() == "65536");
        a <<= 16;
        assert(a.format() == "4294967296");
        a <<= 32;
        assert(a.size()==2);
        assert(a.digit(0)==0);
        assert(a.digit(1)==1);
        a >>= 1;
        assert(a.size()==1);
        a >>= 63;
        assert(a.size()==1);
        assert(a.digit(0)==1);
        a >>= 1;
        assert(a.size()==0);
    }

    {
        NNI a(1),b(7),c,d;
        a <<= 1;
        a <<= 63;
        b <<= 1;
        b <<= 63;
        c = a + b;

        assert(c.size()==2);
        assert(c.digit(0)==0);
        assert(c.digit(1)==8);

        a = NNI(10000);
        a <<= 1;
        a <<= 63;
        b = NNI(30000);
        b <<= 1;
        b <<= 63;
        c = NNI(1234);
        d = a + c + b + c;
        assert(d.size()==2);
        assert(d.digit(0)==1234*2);
        assert(d.digit(1)==40000);
    }

    {
        NNI a(1),b(7),c,d;
        a <<= 1;
        a <<= 63;
        b <<= 1;
        b <<= 63;
        c = b - a;

        assert(c.size()==2);
        assert(c.digit(0)==0);
        assert(c.digit(1)==6);

        a = NNI(10000);
        a <<= 1;
        a <<= 63;
        b = NNI(30000);
        b <<= 1;
        b <<= 63;
        c = NNI(1234);
        d = (b+c) - (a+c);
        assert(d.size()==2);
        assert(d.digit(0)==0);
        assert(d.digit(1)==20000);
    }

    {
        NNI a(3),b(7),c,d;
        a <<= 1;
        a <<= 63;
        b <<= 1;
        b <<= 63;
        c = b * a;
        d = a * b;
        assert(c==d);
        assert(c.size()==3);
        assert(c.digit(0)==0);
        assert(c.digit(1)==0);
        assert(c.digit(2)==21);
    }

    {
        NNI a(4);
        a <<= 32;
        a <<= 32;
        a = a + NNI(3);
        a <<= 32;
        a <<= 32;
        a = a + NNI(2);

        NNI b(7);
        b <<= 32;
        b <<= 32;
        b = b + NNI(6);
        b <<= 32;
        b <<= 32;
        b = b + NNI(5);

        //          4   3   2
        //       x  7   6   5
        //       ------------
        //         20  15  10
        //     24  18  12
        // 28  21  14

        NNI c = a * b;
        assert(c.size()==5);
        assert(c.digit(0) == 2*5);
        assert(c.digit(1) == 3*5+2*6);
        assert(c.digit(2) == 4*5+6*3+7*2);
        assert(c.digit(3) == 4*6+7*3);
        assert(c.digit(4) == 4*7);
    }

    {
        NNI a(1UL<<63);
        a <<= 1;
        a <<= 63;
        a = a + NNI(1UL<<63);
        a <<= 1;
        a <<= 63;
        a = a + NNI(1UL<<63);

        //                    1000  1000  1000
        //                  x 1000  1000  1000
        //                  ------------------
        //               100  0100  0100  0000
        //        0100  0100  0100  0000
        //  0100  0100  0100  0000
        //  ----------------------------------
        //  0100  1000  1100  1000  0100  0000

        NNI c = a * a;
        assert(c.size()==6);
        assert(c.digit(0) == 0);
        assert(c.digit(1) == 1UL<<62);
        assert(c.digit(2) == 1UL<<63);
        assert(c.digit(3) == 3UL<<62);
        assert(c.digit(4) == 1UL<<63);
        assert(c.digit(5) == 1UL<<62);
    }

    {
        NNI a(1),b(1);
        assert(!(a<b));
        assert(!(b<a));
    }
    {
        NNI a(1),b(2);
        assert(a<b);
        assert(!(b<a));

        NNI c(1);
        c <<= 32;
        c <<= 32;

        a = a + b;
        assert(!(a<b));
        assert(b<a);

        b = b + c;
        assert(a<b);
        assert(!(b<a));

        c <<= 32;
        c <<= 32;
        b = b + c;
        assert(!(b<a));
        assert(a<b);
    }
    {
        NNI a,b;
        assert(!(a<b));
        assert(!(b<a));
        a = a + NNI(1);
        assert(!(a<b));
        assert(b<a);
    }

    {
        NNI q,r,u,v;

        for (NNI::digit_t i=0; i<20; i++)
            for (NNI::digit_t j=1; j<25; j++) {
                u = NNI(i);
                v = NNI(j);
                divide(q,r,u,v);

                if (i/j) {
                    assert(q.size()==1);
                    assert(q.digit(0)==i/j);
                }
                else 
                    assert(q.size()==0);

                if (i%j) {
                    assert(r.size()==1);
                    assert(r.digit(0)==i%j);
                }
                else {
                    //std::cout << u << "\n";
                    //std::cout << v << "\n";
                    //std::cout << q << "\n";
                    //std::cout << r << "\n";
                    assert(r.size()==0);
                }
            }

        for (NNI::digit_t i=0; i<20; i++)
            for (NNI::digit_t j=1; j<25; j++) {
                u = NNI(i);
                u <<= 1;
                u <<= 63;
                v = NNI(j);
                v <<= 1;
                v <<= 63;
                divide(q,r,u,v);

                if (i/j) {
                    assert(q.size()==1);
                    assert(q.digit(0)==i/j);
                }
                else 
                    assert(q.size()==0);

                if (i%j) {
                    assert(r.size()==2);
                    assert(r.digit(0)==0);
                    assert(r.digit(1)==i%j);
                }
                else {
                    assert(r.size()==0);
                }
            }

        for (NNI::digit_t i=0; i<20; i++)
            for (NNI::digit_t j=1; j<25; j++) {
                u = NNI(i);
                u <<= 1;
                u <<= 63;
                u <<= 1;
                u <<= 63;
                v = NNI(j);
                v <<= 1;
                v <<= 63;
                v <<= 1;
                v <<= 63;
                divide(q,r,u,v);

                if (i/j) {
                    assert(q.size()==1);
                    assert(q.digit(0)==i/j);
                }
                else 
                    assert(q.size()==0);

                if (i%j) {
                    assert(r.size()==3);
                    assert(r.digit(0)==0);
                    assert(r.digit(1)==0);
                    assert(r.digit(2)==i%j);
                }
                else {
                    assert(r.size()==0);
                }
            }
    }

    {
        NNI a("123456789012345678901234567890");
        assert(a.size() == 2);
        assert(a.format() == "123456789012345678901234567890");
    }
    {
        NNI a("1234567890123456789012345678901234567890");
        assert(a.format() == "1234567890123456789012345678901234567890");
    }

    {
        NNI a(2),e(64),b("999999999999999999999999999999999999999");
        NNI r = expmod(a,e,b);
        assert(r.size()==2);
        assert(r.digit(0)==0);
        assert(r.digit(1)==1);

        b = NNI(3);
        r = expmod(a,e,b);
        assert(r.size()==1);
        assert(r.digit(0)==1);
    }

    {
        NNI a("999999999999999999999999999999999999999"),e(3),b(65537);
        NNI r = expmod(a,e,b);
        NNI c = a*a*a;
        NNI d = c % b;
        assert(r == d);
    }
    {
        NNI a("999999999999999999999999999999999999999"),b(65537);
        NNI r = expmod(a,NNI(7),b);
        NNI c = a*a*a*a*a*a*a;
        NNI d = c % b;
        assert(r == d);
    }

    {
        VNNI a(7);
        assert(a.size() == 1);
        assert(a.digit(0) == 7);

        a = VNNI(123456789012345);
        assert(a.digit(0) == 123456789012345);
        assert(a.size() == 1);
    }
    {
        VNNI a("1");
        assert(a.digit(0) == 1);
        assert(a.size() == 1);
    }
    {
        VNNI a("3");
        assert(a.digit(0) == 3);
        assert(a.size() == 1);

        VNNI b;
        b = a*a;
        assert(b.digit(0) == 9);
        assert(b.size()==1);

        VNNI c;
        c = b*a;
        assert(c.digit(0) == 27);
        assert(c.size()==1);
    }
    {
        VNNI a("12");
        assert(a.digit(0) == 12);
        assert(a.size() == 1);
    }
    {
        VNNI a("123");
        assert(a.digit(0) == 123);
        assert(a.size() == 1);
    }

    {
        VNNI a;
        assert(a.format() == "0");
    }
    {
        VNNI a(7);
        assert(a.format() == "7");
    }
    {
        VNNI a(123456789012345);
        assert(a.format() == "123456789012345");
    }
    {
        VNNI a(99);
        assert(a.format() == "99");
    }

    {
        VNNI a(1);
        a <<= 1;
        assert(a.format() == "2");
        a <<= 1;
        assert(a.format() == "4");
        a <<= 1;
        assert(a.format() == "8");
        a <<= 1;
        assert(a.format() == "16");
        a <<= 4;
        assert(a.format() == "256");
        a <<= 8;
        assert(a.format() == "65536");
        a <<= 16;
        assert(a.format() == "4294967296");
        a <<= 32;
        assert(a.size()==2);
        assert(a.digit(0)==0);
        assert(a.digit(1)==1);
        a >>= 1;
        assert(a.size()==1);
        a >>= 63;
        assert(a.size()==1);
        assert(a.digit(0)==1);
        a >>= 1;
        assert(a.size()==0);
    }

    {
        VNNI a(1),b(7),c,d;
        a <<= 1;
        a <<= 63;
        b <<= 1;
        b <<= 63;
        c = a + b;

        assert(c.size()==2);
        assert(c.digit(0)==0);
        assert(c.digit(1)==8);

        a = VNNI(10000);
        a <<= 1;
        a <<= 63;
        b = VNNI(30000);
        b <<= 1;
        b <<= 63;
        c = VNNI(1234);
        d = a + c + b + c;
        assert(d.size()==2);
        assert(d.digit(0)==1234*2);
        assert(d.digit(1)==40000);
    }

    {
        VNNI a(1),b(7),c,d;
        a <<= 1;
        a <<= 63;
        b <<= 1;
        b <<= 63;
        c = b - a;

        assert(c.size()==2);
        assert(c.digit(0)==0);
        assert(c.digit(1)==6);

        a = VNNI(10000);
        a <<= 1;
        a <<= 63;
        b = VNNI(30000);
        b <<= 1;
        b <<= 63;
        c = VNNI(1234);
        d = (b+c) - (a+c);
        assert(d.size()==2);
        assert(d.digit(0)==0);
        assert(d.digit(1)==20000);
    }

    {
        VNNI a(3),b(7),c,d;
        a <<= 1;
        a <<= 63;
        b <<= 1;
        b <<= 63;
        c = b * a;
        d = a * b;
        assert(c==d);
        assert(c.size()==3);
        assert(c.digit(0)==0);
        assert(c.digit(1)==0);
        assert(c.digit(2)==21);
    }

    {
        VNNI a(4);
        a <<= 32;
        a <<= 32;
        a = a + VNNI(3);
        a <<= 32;
        a <<= 32;
        a = a + VNNI(2);

        VNNI b(7);
        b <<= 32;
        b <<= 32;
        b = b + VNNI(6);
        b <<= 32;
        b <<= 32;
        b = b + VNNI(5);

        //          4   3   2
        //       x  7   6   5
        //       ------------
        //         20  15  10
        //     24  18  12
        // 28  21  14

        VNNI c = a * b;
        assert(c.size()==5);
        assert(c.digit(0) == 2*5);
        assert(c.digit(1) == 3*5+2*6);
        assert(c.digit(2) == 4*5+6*3+7*2);
        assert(c.digit(3) == 4*6+7*3);
        assert(c.digit(4) == 4*7);
    }

    {
        VNNI a(1UL<<63);
        a <<= 1;
        a <<= 63;
        a = a + VNNI(1UL<<63);
        a <<= 1;
        a <<= 63;
        a = a + VNNI(1UL<<63);

        //                    1000  1000  1000
        //                  x 1000  1000  1000
        //                  ------------------
        //               100  0100  0100  0000
        //        0100  0100  0100  0000
        //  0100  0100  0100  0000
        //  ----------------------------------
        //  0100  1000  1100  1000  0100  0000

        VNNI c = a * a;
        assert(c.size()==6);
        assert(c.digit(0) == 0);
        assert(c.digit(1) == 1UL<<62);
        assert(c.digit(2) == 1UL<<63);
        assert(c.digit(3) == 3UL<<62);
        assert(c.digit(4) == 1UL<<63);
        assert(c.digit(5) == 1UL<<62);
    }

    {
        VNNI a(1),b(1);
        assert(!(a<b));
        assert(!(b<a));
    }
    {
        VNNI a(1),b(2);
        assert(a<b);
        assert(!(b<a));

        VNNI c(1);
        c <<= 32;
        c <<= 32;

        a = a + b;
        assert(!(a<b));
        assert(b<a);

        b = b + c;
        assert(a<b);
        assert(!(b<a));

        c <<= 32;
        c <<= 32;
        b = b + c;
        assert(!(b<a));
        assert(a<b);
    }
    {
        VNNI a,b;
        assert(!(a<b));
        assert(!(b<a));
        a = a + VNNI(1);
        assert(!(a<b));
        assert(b<a);
    }

    {
        VNNI q,r,u,v;

        for (VNNI::digit_t i=0; i<20; i++)
            for (VNNI::digit_t j=1; j<25; j++) {
                u = VNNI(i);
                v = VNNI(j);
                divide(q,r,u,v);

                if (i/j) {
                    assert(q.size()==1);
                    assert(q.digit(0)==i/j);
                }
                else 
                    assert(q.size()==0);

                if (i%j) {
                    assert(r.size()==1);
                    assert(r.digit(0)==i%j);
                }
                else {
                    //std::cout << u << "\n";
                    //std::cout << v << "\n";
                    //std::cout << q << "\n";
                    //std::cout << r << "\n";
                    assert(r.size()==0);
                }
            }

        for (VNNI::digit_t i=0; i<20; i++)
            for (VNNI::digit_t j=1; j<25; j++) {
                u = VNNI(i);
                u <<= 1;
                u <<= 63;
                v = VNNI(j);
                v <<= 1;
                v <<= 63;
                divide(q,r,u,v);

                if (i/j) {
                    assert(q.size()==1);
                    assert(q.digit(0)==i/j);
                }
                else 
                    assert(q.size()==0);

                if (i%j) {
                    assert(r.size()==2);
                    assert(r.digit(0)==0);
                    assert(r.digit(1)==i%j);
                }
                else {
                    assert(r.size()==0);
                }
            }

        for (VNNI::digit_t i=0; i<20; i++)
            for (VNNI::digit_t j=1; j<25; j++) {
                u = VNNI(i);
                u <<= 1;
                u <<= 63;
                u <<= 1;
                u <<= 63;
                v = VNNI(j);
                v <<= 1;
                v <<= 63;
                v <<= 1;
                v <<= 63;
                divide(q,r,u,v);

                if (i/j) {
                    assert(q.size()==1);
                    assert(q.digit(0)==i/j);
                }
                else 
                    assert(q.size()==0);

                if (i%j) {
                    assert(r.size()==3);
                    assert(r.digit(0)==0);
                    assert(r.digit(1)==0);
                    assert(r.digit(2)==i%j);
                }
                else {
                    assert(r.size()==0);
                }
            }
    }

    {
        VNNI a("123456789012345678901234567890");
        assert(a.size() == 2);
        assert(a.format() == "123456789012345678901234567890");
    }
    {
        VNNI a("1234567890123456789012345678901234567890");
        assert(a.format() == "1234567890123456789012345678901234567890");
    }

    {
        VNNI a(2),e(64),b("999999999999999999999999999999999999999");
        VNNI r = expmod(a,e,b);
        assert(r.size()==2);
        assert(r.digit(0)==0);
        assert(r.digit(1)==1);

        b = VNNI(3);
        r = expmod(a,e,b);
        assert(r.size()==1);
        assert(r.digit(0)==1);
    }

    {
        VNNI a("999999999999999999999999999999999999999"),e(3),b(65537);
        VNNI r = expmod(a,e,b);
        VNNI c = a*a*a;
        VNNI d = c % b;
        assert(r == d);
    }
    {
        VNNI a("999999999999999999999999999999999999999"),b(65537);
        VNNI r = expmod(a,VNNI(7),b);
        VNNI c = a*a*a*a*a*a*a;
        VNNI d = c % b;
        assert(r == d);
    }

}
