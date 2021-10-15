// RSA encode/decode

#include <iostream>
#include <iomanip>
#include <sstream>
#include <cassert>
using namespace std;
#include "bnni.h"

int find_block_size(const BNNI &n)
{
	BNNI x = n;
	int r = 0;
	while (x.size > 0) {
		shift_right(x,8);
		r++;
	}
	return r-1;
}

int main()
{
    BNNI a,b,e,t;
    string line;

	getline(cin,line);
	bool encode = (line == "encode");

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

	int block_size = find_block_size(b);

    // cout << "blocksize="<<block_size<<endl;

	if (encode) {
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
	    	}
	    	
			BNNI r;
			exp_mod(a,e,b,r);
		
			for (int i=0; i<block_size/4+1; i++) {
			    uint x = i<r.size ? r.digits[i] : 0;
			    result << setfill('0') << setw(8) << hex << x << " ";
			}
		
			msg = block_size>=msg.size() ? "" : msg.substr(block_size);
	    }
    
    	cout << result.str() << endl;
	}
    else {
        stringstream in(msg);
	    while (!in.eof()) {
	    	a.size = block_size/4+1;
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
}
