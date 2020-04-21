#include <stdlib.h>
#include <stdio.h> 

int main(){
	setvbuf(stdin, NULL, _IONBF, 0); 
	setvbuf(stdout, NULL, _IONBF, 0); 

	char buf[15]; 
	
	fgets(buf, 15, stdin); 
	puts(buf); 

	fgets(buf, 15, stdin);
	puts(buf); 	
	return 0; 
} 	
