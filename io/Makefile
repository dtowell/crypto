CPPFLAGS = -g -std=gnu++17 -Wall -Wextra -Werror -Wshadow -Wconversion -mrdseed -mrdrnd -maes

all: rand rand2 xor en64 de64 dekey enaes deaes

test: enaes deaes samp.txt
	./enaes 123456789abcdef0123456789abcdef0 samp.txt t2
	./deaes 123456789abcdef0123456789abcdef0 t2 t3
	xxd -g1 samp.txt > hex
	xxd -g1 t3 > h3
	diff -yq hex h3
	./enaes 123456789abcdef0123456789abcdef0 big.txt t2
	./deaes 123456789abcdef0123456789abcdef0 t2 t3
	xxd -g1 big.txt > hex
	xxd -g1 t3 > h3
	diff -qy hex h3

clean:
	rm -f rand rand2 xor en64 de64 dekey enaes deaes t2 t3 h2 h3 hex
