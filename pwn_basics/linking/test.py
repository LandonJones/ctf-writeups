from pwn import * 
context.terminal = ['tmux', 'splitw', '-h']
context.bits = 64
context.arch = 'amd64' 
 
elf = ELF("./main") 

r = gdb.debug("./main", gdbscript="""
                                    break *%s
                                    """ % (hex(0x00400540)))




#compiler optimization changed printf to puts

log.info("puts GOT %s; puts PLT %s" % (hex(elf.got['puts']), hex(elf.plt['puts']))) 
log.info("fgets GOT %s; fgets PLT %s" % (hex(elf.got['fgets']), hex(elf.plt['fgets']))) 

r.sendline(b'A'*10) 

print(r.recv())

r.sendline(b'A'*10) 

print(r.recv()) 
