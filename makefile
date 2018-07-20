all: myELF

myELF: myELF.o
	gcc -g -Wall -m64 -o myELF myELF.o

myELF.o: myELF.c elf.h

.PHONY: clean

clean:
	rm -f ./*.o myELF