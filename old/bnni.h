// Big Non-negative Integers

typedef unsigned int uint;
typedef unsigned long long ullong;
const int MAX = 120;

// NUMBER(a[0]...a[i]): (...((digits[i]*2^32) + digits[i-1])*2^32 + ...) + digits[0]

struct BNNI {
	// valid: size=0 or (size>0 and digits[size-1]>0)
	// number(a,b): NUMBER(digits[a]..digits[b])
	// number: number(0,size-1)
	
    uint    digits[MAX];
    int     size;
    
	uint	digit(int i) const { return i<size ? digits[i] : 0; }
};

string dump(const BNNI &r);
void add(const BNNI &u,const BNNI &v,BNNI &r); 
bool bigger(const BNNI &u,const BNNI &v);
void subtract(const BNNI &u,const BNNI &v,BNNI &r);
void multiply(const BNNI &u,const BNNI &v,BNNI &r);
void set(BNNI &r,uint n);
void set(BNNI &r,const string &str);
void divide(const BNNI &u,const BNNI &v,BNNI &q,BNNI &r);
string format(const BNNI &n);
void shift_left(BNNI &n,int shift);
void shift_right(BNNI &n,int shift);
void eea(const BNNI &n,const BNNI &p,BNNI &gcd,BNNI &mi);
void exp_mod(const BNNI &a,const BNNI &e,const BNNI &b,BNNI &r);
