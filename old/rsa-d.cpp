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
    set(e,"4635506548953664127");
    set(b,"9000000168000000703");
    string msg = "66c131c3 2288d347 67fc3b0c 5b442cb6\nbefed969 4de51695 048419a5 4fa5b9d8\ncd1e7757 02d08331 b7b543fa 75d9770d";
    block_size = 7;
#else
    set(e,"2753");
    set(b,"3233");
    string msg = "00000660 00000a0a 00000119 000006ed 00000521 00000559 00000b6b 0000087a 00000c6b 000006a0 000002b2 000002e9 000008df";
    block_size = 1;
#endif

    stringstream in(msg);
    while (!in.eof()) {
    	a.size = (block_size+3)/4;
		for (int i=0; i<a.size; i++)
	    	in >> hex >> a.digits[i];
	    while (a.size>0 && a.digits[a.size-1]==0)
	        a.size--;
	    	    
		BNNI r;
		exp_mod(a,e,b,r);
	
	    string result="";
		for (int i=0; i<block_size; i++) {
		    uint x = r.size>0 ? r.digits[0] : 0;
		    result = string(1,(char)(x & 0xFF)) + result;
		    shift_right(r,8);
		}	
		cout << result;
	}
    
    cout << endl;
}
