#!/usr/bin/env python


from pwn import *

BINARY = "./pwnshop"
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


def solve():
    io = conn()
    io.interactive()


if __name__ == "__main__":
    solve()
