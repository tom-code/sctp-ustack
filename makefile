
CXXFLAGS=-std=c++11 -O3 -Wall -g

s: s.o
	g++ -o s s.o -std=c++11 -lpthread

clean:
	rm -f s s.o
