CPPFLAGS = -g -std=gnu++17 -Wall -Wextra -Werror -Wshadow -Wconversion -mrdseed -mrdrnd -maes

all: rand rand2 xor en64 de64 dekey enaes deaes

test: enaes deaes samp
	./enaes 123456789abcdef0123456789abcdef0 samp t2
	./deaes 123456789abcdef0123456789abcdef0 t2 t3
	xxd -g1 t2 > h2
	xxd -g1 t3 > h3
	diff -y h2 h3

clean:
	rm rand rand2 xor en64 de64 dekey enaes deaes t2 t3 h2 h3
