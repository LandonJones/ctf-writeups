all: intro.c
	gcc intro.c -o intro
	patchelf --set-rpath . --set-interpreter ./ld-2.23.so intro
clean: 
	rm -rf core
