all: skeleton

skeleton: skeleton.o
	ld -m elf_i386  skeleton.o -o skeleton

skeleton.o: skeleton.s
	nasm -f elf skeleton.s -o skeleton.o
	nasm -f elf skeleton.s -l smple.lst

.PHONY: clean

clean: 
	rm -f *.o skeleton