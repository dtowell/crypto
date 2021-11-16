#include <iostream>
#include <cassert>
#include <random>
#include "crypto.h"
using namespace std;
using namespace crypto;

void set_n_rand_digits(NNI &n,size_t digits)
{
    assert(digits > 0);
    buffer_t buffer;
    rand_rdrand(digits*sizeof(NNI::digit_t),buffer);
    assert(buffer.size()>=digits);
    n = NNI(buffer);
    assert(!(n==0));
}

std::random_device rd;

void test(int min_digits,int max_digits)
{
    NNI a,b,c,d,e,f;
    std::uniform_int_distribution<int> roll(min_digits,max_digits);

    set_n_rand_digits(a,roll(rd));
    set_n_rand_digits(b,roll(rd));
    set_n_rand_digits(c,roll(rd));
    set_n_rand_digits(d,roll(rd));

    // test add & subtract
    f = a+b+c+d;
    e = f-a-b-c-d;
    if (!(e == 0)) {
        cout << "a=" << a;
        cout << " b=" << b;
        cout << " c=" << c;
        cout << " d=" << d;
        cout << " a+b+c+d-a-b-c-d=" << f <<endl<<endl;        
    }
    
    NNI::digit_t x = std::uniform_int_distribution<int>(1,1000)(rd);
    NNI r{x};
    f = a*b*c*d+r;
    divide(e,r,f,a);
    if (!(r == x)) {
        cout << "a=" << a;
        cout << " b=" << b;
        cout << " c=" << c;
        cout << " d=" << d;
        cout << " x=" << x << endl;
        cout << "a*b*c*d+x=" << f <<endl;
        cout << "(a*b*c*d+x)/a=" << e <<endl;
        cout << "a*b*c*d+x mod a=" << r <<endl<<endl;
    }

    f = e+r;
    divide(e,r,f,b);
    if (!(r == x)) {
        cout << "a=" << a;
        cout << " b=" << b;
        cout << " c=" << c;
        cout << " d=" << d;
        cout << " x=" << x;
        cout << " (a*b*c*d+x)/a mod b=" << r <<endl<<endl;
    }     

    f = e+r;
    divide(e,r,f,c);
    if (!(r == x)) {
        cout << "a=" << a;
        cout << " b=" << b;
        cout << " c=" << c;
        cout << " d=" << d;
        cout << " x=" << x;
        cout << " ((a*b*c*d+x)/a+x)/b mod c=" << r <<endl<<endl;
    }     

    f = e+r;
    divide(e,r,f,d);
    if (!(r == x)) {
        cout << "a=" << a;
        cout << " b=" << b;
        cout << " c=" << c;
        cout << " d=" << d;
        cout << " x=" << x;
        cout << " (((a*b*c*d+x)/a+x)/b+x/c) mod d=" << r <<endl<<endl;
    }     
    if (!(e == 1)) {
        cout << "a=" << a;
        cout << " b=" << b;
        cout << " c=" << c;
        cout << " d=" << d;
        cout << " x=" << x;
        cout << " ((((a*b*c*d+x)/a+x)/b+x)/c+x)/d=" << e <<endl<<endl;
    }     
}

int main(int argc,char *argv[])
{   
    if (argc < 2) {
        cout << "usage: " << argv[0] << " <min-digits> [<max-digits>]\n";
        exit(1);
    }
 
    int min = stoi(argv[1]);
    int max = argc>2 ? stoi(argv[2]) : min;

    cout << "testing " << (min*sizeof(NNI::digit_t)*8-7) << ".." << max*sizeof(NNI::digit_t)*8 << " bits\n";

    while (true) {
        test(min,max);
        cout << "." << flush;
    }
}
