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
        assert(hash_sha512(x,hash));
        std::cout << hash;
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
}
