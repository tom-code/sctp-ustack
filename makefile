
CXXFLAGS=-std=c++11 -O3 -Wall

s: s.o
	g++ -o s s.o -std=c++11

clean:
	rm -f s s.o
