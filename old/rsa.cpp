// Big Non-negative Integers

#include <iostream>
#include <iomanip>
#include <sstream>
#include <cassert>
using namespace std;
#include "bnni.h"

int main()
{
    int block_size;
    BNNI a,b,e,t;
    string line;

#if 0
    getline(cin,line); 
    set(e,line);
        
    getline(cin,line);
    set(b,line);

    getline(cin,line);
    string msg = "";
    while (line != "") {
    	msg += "\n" + line;
    	getline(cin,line);
    }
    msg = msg.substr(1);
#elif 1
    set(b,"9000000162000000648");
    set(e,"100000007");
    eea(b,e,a,t);
    cout << "gcd=" << format(a) << " mi=" << format(t) << endl;

    set(e,"100000007");
    set(b,"9000000168000000703"); // 3000000019 * 3000000037
    string msg = "abcdefghijklmnopqrstuvwxyz\n0123456789";
    block_size = 7;
#else
    set(b,3120);
    set(e,17);
    eea(b,e,a,t);
    cout << "gcd=" << format(a) << " mi=" << format(t) << endl;

    set(e,17);
    set(b,"3233");
    string msg = "abcdefghijklm";
    block_size = 1;    
#endif

    stringstream result;
    while (msg != "") {
        set(a,0);
    	for (int i=0; i<block_size; i++) {
    	    shift_left(a,8);
    	    int c = i<msg.size() ? msg[i] : 0;
    	    BNNI t;
    	    set(t,c);
    	    BNNI t2;
    	    add(a,t,t2);
    	    a = t2;
	    //cout << "adding " << c << " a=" << format(a) << endl;
    	}
    	
cout << format(a) << "^" << format(e) << " mod " << format(b) << endl;
    	
	BNNI r;
	exp_mod(a,e,b,r);
	
	//cout << "r=" << format(r) << endl;
    	
	for (int i=0; i<(block_size+3)/4; i++) {
	    uint x = i<r.size ? r.digits[i] : 0;
	    result << setfill('0') << setw(8) << hex << x << " ";
	}
	
	msg = block_size>=msg.size() ? "" : msg.substr(block_size);
    }
    
    cout << result.str() << endl;
}
