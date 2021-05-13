#!/usr/bin/env python3


from pwn import *

BINARY = "./ropmev2"
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

    input("PAUSE...")
    payload = [byte.to_bytes(1, 'little') for byte in range(256)]
    io.sendlineafter("Please dont hack me\n", flat(payload))

    io.interactive()


if __name__ == "__main__":
    solve()
