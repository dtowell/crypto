// Big Non-negative Integers

#include <iostream>
#include <sstream>
#include <cassert>
#include <cstdlib>
using namespace std;
#include "bnni.h"


uint bigrand() {
    uint r;
    while (!(r=rand()));
    return (r<<16)+rand();
}

int test()
{
    BNNI a,b,c,d,e,f;

    set(a,bigrand());
    set(b,bigrand());
    set(c,bigrand());
    set(d,bigrand());
    
    // test add & subtract
    set(e,0);
    add(e,e,f);
    add(a,f,e);
    add(b,e,f);
    add(c,f,e);
    add(d,e,f);
    subtract(f,a,e);
    subtract(e,b,f);
    subtract(f,c,e);
    subtract(e,d,f);
    if (f.size != 0) {
        cout << "a=" << format(a);
        cout << " b=" << format(b);
        cout << " c=" << format(c);
        cout << " d=" << format(d);
        cout << " a+b+c+d-a-b-c-d=" << format(f) <<endl<<endl;        
    }
    
    multiply(a,b,e);
    multiply(e,c,f);
    multiply(f,d,e);
    int x = (rand() % 1000)+1;
    BNNI r;
    set(r,x);
    add(e,r,f);
    divide(f,a,e,r);
    if (r.size!=1 || r.digits[0] != x) {
        cout << "a=" << format(a);
        cout << " b=" << format(b);
        cout << " c=" << format(c);
        cout << " d=" << format(d);
        cout << " x=" << x << endl;
        cout << "a*b*c*d+x=" << format(f) <<endl;
        cout << "(a*b*c*d+x)/a=" << format(e) <<endl;
        cout << "a*b*c*d+x mod a=" << format(r) <<endl<<endl;
    }     

    add(e,r,f);
    divide(f,b,e,r);
    if (r.size!=1 || r.digits[0] != x) {
        cout << "a=" << format(a);
        cout << " b=" << format(b);
        cout << " c=" << format(c);
        cout << " d=" << format(d);
        cout << " x=" << x;
        cout << " (a*b*c*d+x)/a mod b=" << format(r) <<endl<<endl;
    }     

    add(e,r,f);
    divide(f,c,e,r);
    if (r.size!=1 || r.digits[0] != x) {
        cout << "a=" << format(a);
        cout << " b=" << format(b);
        cout << " c=" << format(c);
        cout << " d=" << format(d);
        cout << " x=" << x;
        cout << " ((a*b*c*d+x)/a+x)/b mod c=" << format(r) <<endl<<endl;
    }     

    add(e,r,f);
    divide(f,d,e,r);
    if (r.size!=1 || r.digits[0] != x) {
        cout << "a=" << format(a);
        cout << " b=" << format(b);
        cout << " c=" << format(c);
        cout << " d=" << format(d);
        cout << " x=" << x;
        cout << " (((a*b*c*d+x)/a+x)/b+x/c) mod d=" << format(r) <<endl<<endl;
    }     
    if (e.size!=1 || e.digits[0] != 1) {
        cout << "a=" << format(a);
        cout << " b=" << format(b);
        cout << " c=" << format(c);
        cout << " d=" << format(d);
        cout << " x=" << x;
        cout << " ((((a*b*c*d+x)/a+x)/b+x)/c+x)/d=" << format(e) <<endl<<endl;
    }     
}

int main()
{
    /*
    BNNI a,b,c,d;
    set(a,"11121414247859027596774433882112868");
    set(b,"3091202048");
    divide(a,b,c,d);
    cout << a.size << endl;
    cout << format(d) << endl;
    cout << format(c) << endl;
    cout << "3597763612719703916544000" << endl;
    */
    
    srand(time(NULL));
 
    while (true)
        test();
}
