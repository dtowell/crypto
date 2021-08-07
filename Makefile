CPPFLAGS = -g -std=gnu++17 -Wall -Wextra -Werror -Wshadow -Wconversion -mrdseed -mrdrnd -maes

all: rand xor en64 de64 dekey enaes deaes

crypto.o: crypto.cpp

rand: rand.cpp crypto.o

xor: xor.cpp crypto.o

en64: en64.cpp crypto.o

de64: de64.cpp crypto.o

dekey: dekey.cpp crypto.o

enaes: enaes.cpp crypto.o

deaes: deaes.cpp crypto.o

tests: tests.cpp crypto.o

test_all: test_crypto test_aes

test_crypto: tests
	valgrind -q ./tests

test_aes: enaes deaes samp.txt
	valgrind -q ./enaes 123456789abcdef0123456789abcdef0 samp.txt t2
	valgrind -q ./deaes 123456789abcdef0123456789abcdef0 t2 t3
	xxd -g1 samp.txt > hex
	xxd -g1 t3 > h3
	diff -qy hex h3
	valgrind -q ./enaes 123456789abcdef0123456789abcdef0 big.txt t2
	valgrind -q ./deaes 123456789abcdef0123456789abcdef0 t2 t3
	xxd -g1 big.txt > hex
	xxd -g1 t3 > h3
	diff -qy hex h3

clean:
	rm -f *.o rand rand2 xor en64 de64 dekey enaes deaes t2 t3 h2 h3 hex