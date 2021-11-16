#include <iostream>
#include <cassert>
#include <random>
#include "crypto.h"
using namespace std;
using namespace crypto;

void set_n_rand_digits(nni_t &n,size_t digits)
{
    buffer_t buffer;
    rand_rdrand(digits*sizeof(digit_t),buffer);
    n.resize(digits);
    std::copy(buffer.begin(),buffer.end(),reinterpret_cast<uint8_t *>(&n[0]));
}

std::random_device rd;

void test(int min_digits,int max_digits)
{
    nni_t a,b,c,d,e,f;
    std::uniform_int_distribution<int> roll(min_digits,max_digits);

    set_n_rand_digits(a,roll(rd));
    set_n_rand_digits(b,roll(rd));
    set_n_rand_digits(c,roll(rd));
    set_n_rand_digits(d,roll(rd));

    // test add & subtract
    set(e,0);
    add(f,e,e);
    add(e,a,f);
    add(f,b,e);
    add(e,c,f);
    add(f,d,e);
    subtract(e,f,a);
    subtract(f,e,b);
    subtract(e,f,c);
    subtract(f,e,d);
    if (f.size() != 0) {
        cout << "a=" << format(a);
        cout << " b=" << format(b);
        cout << " c=" << format(c);
        cout << " d=" << format(d);
        cout << " a+b+c+d-a-b-c-d=" << format(f) <<endl<<endl;        
    }
    
    multiply(e,a,b);
    multiply(f,e,c);
    multiply(e,f,d);
    digit_t x = std::uniform_int_distribution<int>(1,1000)(rd);
    nni_t r;
    set(r,x);
    add(f,e,r);
    divide(e,r,f,a);
    if (r.size()!=1 || r[0] != x) {
        cout << "a=" << format(a);
        cout << " b=" << format(b);
        cout << " c=" << format(c);
        cout << " d=" << format(d);
        cout << " x=" << x << endl;
        cout << "a*b*c*d+x=" << format(f) <<endl;
        cout << "(a*b*c*d+x)/a=" << format(e) <<endl;
        cout << "a*b*c*d+x mod a=" << format(r) <<endl<<endl;
    }

    add(f,e,r);
    divide(e,r,f,b);
    if (r.size()!=1 || r[0] != x) {
        cout << "a=" << format(a);
        cout << " b=" << format(b);
        cout << " c=" << format(c);
        cout << " d=" << format(d);
        cout << " x=" << x;
        cout << " (a*b*c*d+x)/a mod b=" << format(r) <<endl<<endl;
    }     

    add(f,e,r);
    divide(e,r,f,c);
    if (r.size()!=1 || r[0] != x) {
        cout << "a=" << format(a);
        cout << " b=" << format(b);
        cout << " c=" << format(c);
        cout << " d=" << format(d);
        cout << " x=" << x;
        cout << " ((a*b*c*d+x)/a+x)/b mod c=" << format(r) <<endl<<endl;
    }     

    add(f,e,r);
    divide(e,r,f,d);
    if (r.size()!=1 || r[0] != x) {
        cout << "a=" << format(a);
        cout << " b=" << format(b);
        cout << " c=" << format(c);
        cout << " d=" << format(d);
        cout << " x=" << x;
        cout << " (((a*b*c*d+x)/a+x)/b+x/c) mod d=" << format(r) <<endl<<endl;
    }     
    if (e.size()!=1 || e[0] != 1) {
        cout << "a=" << format(a);
        cout << " b=" << format(b);
        cout << " c=" << format(c);
        cout << " d=" << format(d);
        cout << " x=" << x;
        cout << " ((((a*b*c*d+x)/a+x)/b+x)/c+x)/d=" << format(e) <<endl<<endl;
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

    cout << "testing " << (min*sizeof(digit_t)*8-7) << ".." << max*sizeof(digit_t)*8 << " bits\n";

    while (true) {
        test(min,max);
        cout << "." << flush;
    }
}
