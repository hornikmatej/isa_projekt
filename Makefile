# author: Matej Hornik, xhorni20
# Projekt: ISA, projekt (Klient POP3 s podporou TLS)
# date: 15.10.2021

EXEC = popcl
CXX = g++
CXXFLAGS = -std=c++17 -Wall 
LDLIBS = -lpcap -lssl -lcrypto
LDFLAGS = -L/usr/local/ssl/lib

all: $(EXEC)

$(EXEC): popcl.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $^ $(LDLIBS) 

.PHONY: 
clean:
	rm -f $(EXEC) *.o
zip:
	zip xhorni20.zip manual.pdf Makefile popcl.cpp README