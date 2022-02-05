#variables:

THIS_DIR := $(dir $(abspath $(firstword $(MAKEFILE_LIST))))


#commands:

all:
	clang++ main.cpp include/Antivirus.hpp src/Antivirus.cpp -std=c++2a -lstdc++fs

clean:
	rm -f a.out
	rm -f AV.log
	rm -f include/antivirus.hpp.gch
run:
	./a.out $(THIS_DIR)

allgpp:
	g++ -I./ -std=gnu++2a -o a.out include/Antivirus.hpp src /Antivirus.cpp main.cpp -lstdc++fs
