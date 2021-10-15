// Big Non-negative Integers

#include <iostream>
#include <sstream>
#include <cassert>
using namespace std;
#include "bnni.h"

int main()
{
    BNNI a,b,c,d;

    string s,t;
    cin >> s;
    cin >> t;
    
    set(a,s);
    set(b,t);
    cout << "a = " << format(a) << endl;
    cout << "b = " << format(b) << endl;
    
    add(a,b,c);
    cout << "a+b = " << format(c) << endl;
    
    subtract(a,b,c);
    cout << "a-b = " << format(c) << endl;
    
    multiply(a,b,c);
    cout << "a*b = " << format(c) << endl;
    
    divide(a,b,c,d);
    cout << "a/b = " << format(c) << endl;
    cout << "a%b = " << format(d) << endl;
}
