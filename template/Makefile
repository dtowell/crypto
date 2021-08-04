CPPFLAGS = -g -std=gnu++17 -Wall -Wextra -Werror -Wshadow -Wconversion -mrdseed -mrdrnd -maes

rand: rand.cpp crypto.cpp

tests: tests.cpp crypto.cpp

test: tests
	valgrind -q ./tests

clean:
	rm -f *.o rand tests
