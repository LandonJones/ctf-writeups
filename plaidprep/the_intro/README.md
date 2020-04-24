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
The bug in this program UAF which leads to a double free which can be abused to aquire an arbitrary write. 
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
From the alloc function, we can also see that we only get fastbin chunk sizes (this matters for getting a libc leak).  
### Getting A Heap Leak 
Alright, with these vulnerabilities in mind
### The Fastbin Dup Technique 

### Turning A Heap Leak Into A LIBC Leak 

### Where to write with RELRO?? 




