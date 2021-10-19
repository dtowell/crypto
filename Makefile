CPPFLAGS = -g -std=gnu++17 -Wall -Wold-style-cast -Wextra -Werror -Wshadow -Wconversion -mrdseed -mrdrnd -maes

all: rand xor en64 de64 dekey enaesecb deaesecb enaescbc deaescbc sha

crypto.o: crypto.cpp

rand: rand.cpp crypto.o

xor: xor.cpp crypto.o

en64: en64.cpp crypto.o

de64: de64.cpp crypto.o

dekey: dekey.cpp crypto.o

enaesecb: enaesecb.cpp crypto.o

deaesecb: deaesecb.cpp crypto.o

enaescbc: enaescbc.cpp crypto.o

deaescbc: deaescbc.cpp crypto.o

sha: sha.cpp crypto.o

tests: tests.cpp crypto.o

torture: torture.cpp crypto.o

test_crypto: tests
	valgrind -q ./tests

test_aes: enaesecb deaesecb enaescbc deaescbc samp.txt
	valgrind -q ./enaesecb 123456789abcdef0123456789abcdef0 samp.txt t2
	valgrind -q ./deaesecb 123456789abcdef0123456789abcdef0 t2 t3
	xxd -g1 samp.txt > hex
	xxd -g1 t3 > h3
	diff -qy hex h3
	valgrind -q ./enaesecb 123456789abcdef0123456789abcdef0 big.txt t2
	valgrind -q ./deaesecb 123456789abcdef0123456789abcdef0 t2 t3
	xxd -g1 big.txt > hex
	xxd -g1 t3 > h3
	diff -qy hex h3
	valgrind -q ./enaescbc 123456789abcdef0123456789abcdef0 0102 samp.txt t2
	valgrind -q ./deaescbc 123456789abcdef0123456789abcdef0 0102 t2 t3
	xxd -g1 samp.txt > hex
	xxd -g1 t3 > h3
	diff -qy hex h3
	valgrind -q ./enaescbc 123456789abcdef0123456789abcdef0 0123456789abcdef big.txt t2
	valgrind -q ./deaescbc 123456789abcdef0123456789abcdef0 0123456789abcdef t2 t3
	xxd -g1 big.txt > hex
	xxd -g1 t3 > h3
	diff -qy hex h3

clean:
	rm -f *.o rand rand2 xor en64 de64 dekey enaesecb deaesecb enaescbc deaescbc sha tests t2 t3 h2 h3 hex
