# GOT/PLT for Pwners

## Exploring the GOT and PLT 
When programs are dynamically linked, the addresses of functions that exist in shared libraries (printf, malloc) are not known until runtime. The GOT (Global Offset Table) and PLT (Procedure Linkage Table) exist to avoid this address resolution until the program actually needs to use the function imported from the library. This technique is known as lazy binding, which is an optimization based on the fact that programs might not need all functions that they import during every run of a program.

In order to understanding how these tables are filled during the runtime of the program, let's debug a really useless C-program in GDB and trace the path of execution from the initial call to the library functions all the way to the PLT.  

```C
#include <stdlib.h>
#include <stdio.h> 

int main(){ 
        char buf[15]; 

        fgets(buf, 15, stdin); 
        puts(buf); 

        fgets(buf, 15, stdin);
        puts(buf); 
        return 0; 
} 
```

```sh
gcc -no-pie main.c -o main 
```
Using the `test.py` program, it sets one breakpoint at the PLT entry for puts. When running the program, let's check how the GOT entry for changes from the first time the program hits that PLT entry to the second time. 

To get `test.py` working, you'll need to install tmux. Once you have that installed, just type `tmux` in your terminal and you can run `test.py`. 

For your GDB output to look like the screenshots below, you'll need [Pwndbg](https://github.com/pwndbg/pwndbg). 

After running `python3 test.py` you terminal should look like 
![pic1](screenshots/initial.png) 

Type `c` to continue to the next breakpoint which will be the `plt` entry of puts. 

To visualize the assembly output at an address type `x/3i addr` and you can replace 3 with any positive integer you'd like.
![pic2](screenshots/first_got.png) 
From the assembly we see that it immediately jumps to `QWORD PTR [rip + 0x200ad2]`, which GDB handily points out that it is `0x601018` ( sorry it's a little janky). Looking over at the left panel, we see that that is the GOT entry of puts. Let's run `dq` which stands for `dump quad`. We see that the address stored in the GOT entry for is `0x400546` which is the address of the instruction right after the jump to the GOT. So this venture to the GOT was pointless. Then it pushes `0x0` to the stack and jumps to `0x400540`. This address is actually the start of the function where the address of puts in our program's address space is resolved. If we use `x/12i $pc` we can see the whole PLT. 
![pic3](screenshots/plt.png) 
Now we can see that the value that is pushed to the stack serves as an index of the entry in the PLT and that it serves as an argument to the address resolving functon at `0x400540`. Now we continue until the next breakpoint to see how the GOT entry changes. 
![pic4](screenshots/puts.png)  
When we examine the GOT entry now, we see that it is filled with the address of puts in our address space. 

So, in summary, the GOT entries will not be filled with the actual addresses until AFTER the function is first called. 
## GOT Milk Aside 
Now, that we know that, GOT milk makes a little more sense. 

Running `ltrace` on the program shows something odd. They call the function lose before taking our input. This means that the GOT entry of lose is now populated with the address of lose in the address space of our program. Hint: the difference between the addresses between `win` and `lose` is only one byte. 
```sh
root@learning:/ctf/work/ctf-writeups/pwn_basics/linking# ltrace ./gotmilk 
__libc_start_main(0x80485f6, 1, 0xff9c0c74, 0x80486d0 <unfinished ...>
setvbuf(0xf7f00d80, 0, 2, 0)                                                           = 0
setvbuf(0xf7f005c0, 0, 2, 0)                                                           = 0
setvbuf(0xf7f00ce0, 0, 2, 0)                                                           = 0
puts("Simulating loss..."Simulating loss...
)                                                             = 19
lose(0, 1, 0xf7f40940, 194
No flag for you!
)                                                            = 18
printf("Hey you! GOT milk? "Hey you! GOT milk? )                                                          = 19
fgets(what
"what\n", 100, 0xf7f005c0)                                                       = 0xff9c0b5c
printf("Your answer: "Your answer: )                                                                = 13
printf("what\n"what
)                                                                       = 5
lose(0, 1, 0xf7f40940, 0x74616877
No flag for you!
)                                                     = 18
+++ exited (status 0) +++

```

