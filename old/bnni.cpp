// Big Non-negative Integers

#include <iostream>
#include <sstream>
#include <cassert>
using namespace std;
#include "bnni.h"

string dump(const BNNI &r)
{
    stringstream ss;
    for (int i=r.size-1; i>=0; i--)
        ss << r.digits[i] << " ";
    return ss.str();
}

void canonicalize(BNNI &n)
// precondition: n.size>=0
// postcondition: n.valid
{
    while (n.size>0 && n.digits[n.size-1]==0)
    	// n.size>=0 && n.digits[k]=0 for n.size-1<=k<n.size0
        n.size--;
}

void add(const BNNI &u,const BNNI &v,BNNI &r)
// precondition: u.valid, v.valid, r not aliased
// postcondition: r.number = u.number + v.number, r.valid
{
    int m = max(u.size,v.size);
    bool carry = false;
    for (int i=0; i<m; i++) {
		// r.number(0,i-1)+carry = u.number(0,i-1)+v.number(0,i-1), i<=m 
        uint c;
        if (carry) {
            c = u.digit(i) + v.digit(i) + 1;
            carry = c <= u.digit(i); 
        } 
        else {
            c = u.digit(i) + v.digit(i);
            carry = c < u.digit(i); 
        } 
        r.digits[i] = c;
    }
    r.size = m;
    if (carry) { 
        r.size++;
        r.digits[m] = 1;
    }
}

bool bigger(const BNNI &u,const BNNI &v)
// precondition: u.valid, v.valid
// postcondition: bigger(u,v) iff u.number>v.number
{
    if (u.size > v.size)
        return true;
        
    if (u.size < v.size)
        return false;
        
    for (int i=u.size-1; i>=0; i--) {
    	// u.number(i-1,size-1)=v.number(i-1,size-1), i>=-1
        if (u.digits[i] > v.digits[i])
            return true;
        if (u.digits[i] < v.digits[i])
            return false;
    }
    return false;
}

void subtract(const BNNI &u,const BNNI &v,BNNI &r)
// precondition: u.valid, v.valid, r not aliased, u.number >= v.number
// postcondition: r.number = u.number - v.number, r.valid
{
    assert(!bigger(v,u));

    r.size = max(u.size,v.size);
    bool borrow = false;
    for (int i=0; i<r.size; i++) {
    	// r.number(0,i-1) = borrow*2^32 + u.number(0,i-1) - v.number(0,i-1), i<=r.size
        if (borrow) {
            r.digits[i] = u.digit(i) -  v.digit(i) - 1;
            borrow      = u.digit(i) <= v.digit(i);
        }
        else {
            r.digits[i] = u.digit(i) - v.digit(i);
            borrow      = u.digit(i) < v.digit(i);
        } 
    }
	canonicalize(r);
}

void multiply(const BNNI &u,const BNNI &v,BNNI &r)
// precondition: u.valid, v.valid
// postcondition: r.number = u.number * v.number, r.valid 
{
    r.size = u.size+v.size;
    for (int i=0; i<r.size; i++)
        r.digits[i] = 0;
        
    for (int j=0; j<v.size; j++) {
        // j>=v.size, ...
        ullong z = 0;
        for (int i=0; i<u.size || z>0; i++) {
        	// ...
            z += r.digit(j+i);
			z += (ullong)u.digit(i) * (ullong)v.digit(j);
            r.digits[j+i] = (uint)z;
            z >>= 32;
        }
    }
    canonicalize(r);
}

void set(BNNI &r,uint n)
// precondition: n>=0
// postcondition: r.number = n, r.valid
{
    assert(n>=0);
    r.size = 1;
    r.digits[0] = n;
    canonicalize(r);
}

void set(BNNI &r,const string &str)
// precondition: str contains only digits
// postcondition: r.number = decimal expansion given in str
{
    BNNI ten,x,t;

    set(r,0);
    set(ten,10);
    for (int i=0; i<str.size(); i++) {
        // r.number = decimal expansion of str[0]..str[i-1], i<=str.size() 
        multiply(r,ten,t);
        set(x,str[i] - '0');
        add(t,x,r);
    }
}

uint find_qhat(uint un,uint un1,uint un2,uint vn1,uint vn2)
{
    ullong q = ((((ullong)un)<<32)+un1) / (ullong)vn1;
    ullong r = ((((ullong)un)<<32)+un1) % (ullong)vn1;
    if ((q>>32) > 0) {
        q--;
        r += vn1;
    }
    int x=0;
    while ((r>>32)==0 && q*vn2 > (r<<32)+un2) {
        q--;
        r += vn1;
        x++;
    }
    assert(x < 3);
    //cout << x << " ";
    //cout << "u=" << un << "," << un1 << "," << un2 << " v=" << vn1 << "," << vn2 << " q=" << q << endl;
    return (uint)q;        
}

int top_zeros(const BNNI &n)
{
    const uint HALF = 1<<31;
    uint x = n.digits[n.size-1];
    int shift = 0;
    while (x < HALF) {
        x <<= 1;
        shift++;
    }
    return shift;
}

void shift_left(BNNI &n,int shift)
{
    n.digits[n.size] = 0;
    uint bits = 0;
    for (int i=0; i<n.size; i++) {
        uint digit = n.digits[i];
        n.digits[i] = (digit<<shift) + bits;
        bits = shift>0 ? digit>>(32-shift) : 0;
    }
    if (bits > 0)
        n.digits[n.size++] = bits;
}

void shift_right(BNNI &n,int shift)
{
    n.digits[n.size] = 0;
    uint bits = 0;
    for (int i=n.size-1; i>=0; i--) {
        uint digit = n.digits[i];
        n.digits[i] = (digit>>shift) + bits;
        bits = shift>0 ? digit<<(32-shift) : 0;
    }
    canonicalize(n);
}

void divide(const BNNI &u,const BNNI &v,BNNI &q,BNNI &r) 
{
    assert(v.size > 0);
    
    if (u.size==0 || bigger(v,u)) {
        set(q,0);
        r = u;
        return;
    }
    
    if (v.size==1 && u.size<=2) {
        q.size = 1;
        r.size = 1;
        if (u.size==1) {
            q.digits[0] = u.digits[0] / v.digits[0];
            r.digits[0] = u.digits[0] % v.digits[0];
        }
        else {
            ullong n = ((ullong)u.digits[1]<<32)+u.digits[0];
            ullong a = n / v.digits[0];
            q.digits[0] = (uint)a;
            if (a>>32) {
                q.digits[1] = (uint)(a>>32);
                q.size++;
            }
            r.digits[0] = n % v.digits[0];
        }
        if (r.digits[0]==0) r.size = 0;
        return;
    }

    //cout << "div u=" << dump(u) << " v=" << dump(v) << endl;
    BNNI v2 = v;
    int shift = top_zeros(v2);
    shift_left(v2,shift);    
    r = u;
    shift_left(r,shift);
    //cout << "shift=" << shift << endl;
    //cout << "r=" << dump(r) << endl;
    //cout << "v2=" << dump(v2) << endl;
    
    int m = r.size;
    int n = v2.size;
    r.digits[m] = 0;
    q.size = m-n+1;
    for (int k = m-n; k>=0; k--) {
        uint qhat = find_qhat(r.digits[k+n],r.digits[k+n-1],k+n-2<0?0:r.digits[k+n-2],v2.digits[n-1],n-2<0?0:v2.digits[n-2]);
        //cout << "qhat=" << qhat << endl;
        BNNI t;
        t.size = k+1;
        t.digits[k] = qhat;
        for (int i=0; i<k; i++)
            t.digits[i]=0;
            
        BNNI w;
        multiply(v2,t,w); // w = q*v
        if (bigger(w,r)) {
            t.digits[k] = --qhat;
            multiply(v2,t,w);
        }
        //cout << "w=" << dump(w) << endl;
        subtract(r,w,t); // t = u-q*v
        q.digits[k] = qhat;
        //cout << "t=" << dump(t) << endl;
        
        r = t;
        //cout << "r=" << dump(r) << endl;
    }
    shift_right(r,shift);
    while (r.size>0 && r.digits[r.size-1]==0)
        r.size--;
    while (q.size>0 && q.digits[q.size-1]==0)
        q.size--;
}

string format(const BNNI &n)
{
    if (n.size == 0)
        return "0";
    
    BNNI ten;
    set(ten,10);
    
    string digits="";
    BNNI t = n;
    while (t.size > 0) {
        BNNI q,r;
        divide(t,ten,q,r);
        t = q;
        digits = string(1,(int)r.digits[0]+'0') + digits;
    }
    
    return digits; 
}

void eea(const BNNI &n,const BNNI &p,BNNI &gcd,BNNI &mi)
{
    assert(bigger(n,p));
    BNNI newn, oldt, newt;
    gcd = n;
    newn = p;
    set(oldt,0);
    set(newt,1);
    bool neg = true;
    while (newn.size > 0) {
        //cout << format(gcd) << " " << format(newn) << " " << format(oldt) << " " << format(newt) << endl;    
        BNNI q,r;
        divide(gcd,newn,q,r);
        gcd = newn;
        newn = r;
        
        BNNI t,u;
        multiply(q,newt,t);
        add(t,oldt,u);
        oldt = newt;
        newt = u;
        neg = !neg;
    }
    //cout << format(gcd) << " " << format(newn) << " " << format(oldt) << " " << format(newt) << " " << neg << endl; 
        
    if (neg) {
        //cout << format(n) << " - " << format(oldt) << endl;
        subtract(n,oldt,mi);
    }
    else
        mi = oldt;
}

void exp_mod(const BNNI &a,const BNNI &e,const BNNI &b,BNNI &r)
{
    BNNI t,a2,t2;
    set(r,1);
    a2 = a;
    for (int i=0; i<e.size*32; i++) {
        // cout << i << " a2=" << format(a2) << " r=" << format(r) << " " << !!(e.digits[i/32] & (1U<<(i%32))) << endl;
    	if (e.digits[i/32] & (1U<<(i%32))) {
    	    multiply(r,a2,t);
            // cout << " t=" << format(t) << endl;
    	    divide(t,b,t2,r);
    	}
    	multiply(a2,a2,t);
    	divide(t,b,t2,a2);
    }
}


