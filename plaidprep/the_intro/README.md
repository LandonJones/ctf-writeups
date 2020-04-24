# Fastbin Dup / Fastbin Attack
## A Brief Overview of The Heap
Here are some fantastic resources to learn about the GLIBC heap.  
* [https://heap-exploitation.dhavalkapil.com/](https://heap-exploitation.dhavalkapil.com/)
* [https://github.com/shellphish/how2heap](https://github.com/shellphish/how2heap) 
* [https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/](https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/) 
* [https://ctf-wiki.github.io/ctf-wiki/pwn/readme-zh/](https://ctf-wiki.github.io/ctf-wiki/pwn/readme-zh/) 
* [Main arena exploration](http://blog.k3170makan.com/2019/03/glibc-heap-exploitation-basics.html) 

## Example  
### Source Code Analysis 
There are two vulnerabilities: 

The first being the input is not NULL terminated when sending an input of length size bytes. 
```C
void alloc(){
	int index; 
	int size; 
	char* data; 

	puts("Index: "); 

	scanf("%d", &index); 

	if (index < 0 || index >= 10){ 
		return; 
	} 
	puts("Size: "); 
	scanf("%d", &size); 
	
	if (size >= 0x70 || size < 0){ 
		return; 
	} 

	data = (char *)malloc(size); 
	
	puts("Data"); 

	read(0, data, size); // sending size bytes will prevent the input from being null terminated 
	
	chungus[index] = data; 
}
```
The second being a UAF which leads to a double free if the delete function
```C
void delete(){ 
	int index; 
	puts("Index"); 
	scanf("%d", &index); 

	if (index < 0 || index >= 10){ 
		return;
	} 

	free(chungus[index]); // there is no check that the same pointer is not passed in twice
} 
```

### Getting A Heap Leak 

### The Fastbin Dup Technique 

### Turning A Heap Leak Into A LIBC Leak 

### Where to write with RELRO?? 




