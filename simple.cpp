#include "crypto.h"

using namespace crypto;

int main()
{
    {
        NNI a(7);
        assert(a.size() == 1);
        assert(a.digit(0) == 7);
    }
    {
        NNI a(123456789012345);
        assert(a.digit(0) == 123456789012345);
        assert(a.size() == 1);
    }
    {
        NNI a(2),b(3);
        assert(a<b);
        NNI c(2,3);
        assert(a<c);
        NNI d(2);
        assert(!(d<a));
        NNI e;
        assert(e<a);
        assert(e<c);
        NNI f(3,4);
        assert(c<f);
        assert(!(f<c));
    }

    void subtract(const NNI &a,const NNI &b)
    {
        assert(a>b || a==b);
        assert(!(b>a));

    }

    {
        NNI a(2),b(3);
        256*256 == 65536
        NNI x(0xffffffffffffffff)
        x = x+NNI(1);
        NNI a(1);
        for (int i=0; i<128; i++)
            a = a+a;

        assert(a == NNI(0,0,1));
        assert(a.size()==3);
        assert(a.digit(0)==0);


        assert(a+b==NNI(5));
        NNI c(2,3);
        assert(a<c);
        NNI d(2);
        assert(!(d<a));
        NNI e;
        assert(e<a);
        assert(e<c);
        NNI f(3,4);
        assert(c<f);
        assert(!(f<c));
    }
    
    {
        NNI a(3);
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
        NNI a(1),b(7),c;
        c = a + b;

        assert(c.size()==1);
        assert(c.digit(0)==8);
        assert(c == NNI(8));
    }

    {
        NNI a(1),b(7),c(256);
        c = c * c;
        c = c * c;
        a = a * c;
        b = a * c;
        c = a + b;

        assert(c.size()==2);
        assert(c.digit(0)==0);
        assert(c.digit(1)==8);
    }

    {
        NNI a(10000),b(30000),c(256),d(1234);
        c = c * c;
        c = c * c;
        a = a * c + d;
        b = a * c + d;
        d = a + b;

        assert(d.size()==2);
        assert(d.digit(0)==1234*2);
        assert(d.digit(1)==40000);
    }

    {
        NNI c(256);
        c = c*c; 
        c = c*c;
        NNI a(4);
        a = a * c + NNI(3);
        a = a * c + NNI(2);

        NNI b(7);
        b = b * c + NNI(6);
        b = b * c + NNI(5);

        //          4   3   2
        //       x  7   6   5
        //       ------------
        //         20  15  10
        //     24  18  12
        // 28  21  14

        c = a * b;
        assert(c.size()==5);
        assert(c.digit(0) == 2*5);
        assert(c.digit(1) == 3*5+2*6);
        assert(c.digit(2) == 4*5+6*3+7*2);
        assert(c.digit(3) == 4*6+7*3);
        assert(c.digit(4) == 4*7);
    }

    std::cout << "so far so good\n";
}
